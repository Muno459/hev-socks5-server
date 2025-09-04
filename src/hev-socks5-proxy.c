/*
 ============================================================================
 Name        : hev-socks5-proxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Socks5 Proxy
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <yaml.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>
#include <hev-socks5-authenticator.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-socks5-worker.h"
#include "hev-socket-factory.h"
#include "hev-socks5-user-mark.h"

#include "hev-socks5-proxy.h"

static int listen_fd = -1;
static unsigned int workers;

static HevTask *task;
static pthread_t *work_threads;
static HevSocketFactory *factory;
static HevSocks5Worker **worker_list;

static void
hev_socks5_proxy_load_file_yaml (HevSocks5Authenticator *auth,
                                 const char *file)
{
    yaml_parser_t parser;
    yaml_document_t doc;
    yaml_node_t *root;
    FILE *fp;

    fp = fopen (file, "r");
    if (!fp) {
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    if (!yaml_parser_initialize (&parser)) {
        fclose (fp);
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    yaml_parser_set_input_file (&parser, fp);
    if (!yaml_parser_load (&parser, &doc)) {
        yaml_parser_delete (&parser);
        fclose (fp);
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    root = yaml_document_get_root_node (&doc);
    if (root && root->type == YAML_SEQUENCE_NODE) {
        yaml_node_item_t *item;
        for (item = root->data.sequence.items.start;
             item < root->data.sequence.items.top; item++) {
            yaml_node_t *node = yaml_document_get_node (&doc, *item);
            if (!node || node->type != YAML_MAPPING_NODE)
                continue;

            char *username = NULL;
            char *password = NULL;
            char *iface = NULL;
            unsigned long mark = 0;

            yaml_node_pair_t *pair;
            for (pair = node->data.mapping.pairs.start;
                 pair < node->data.mapping.pairs.top; pair++) {
                yaml_node_t *k = yaml_document_get_node (&doc, pair->key);
                yaml_node_t *v = yaml_document_get_node (&doc, pair->value);
                if (!k || !v || k->type != YAML_SCALAR_NODE ||
                    v->type != YAML_SCALAR_NODE)
                    continue;
                const char *key = (const char *)k->data.scalar.value;
                const char *val = (const char *)v->data.scalar.value;
                if (0 == strcmp (key, "username"))
                    username = (char *)val;
                else if (0 == strcmp (key, "password"))
                    password = (char *)val;
                else if (0 == strcmp (key, "mark"))
                    mark = strtoul (val, NULL, 0);
                else if (0 == strcmp (key, "iface"))
                    iface = (char *)val;
            }

            if (username && password) {
                HevSocks5UserMark *user;
                user = hev_socks5_user_mark_new (username, strlen (username),
                                                 password, strlen (password),
                                                 (unsigned int)mark);
                if (!user)
                    continue;
                if (iface && iface[0] != '\0')
                    user->iface = strdup (iface);
                if (hev_socks5_authenticator_add (auth,
                                                  HEV_SOCKS5_USER (user)) < 0)
                    hev_object_unref (HEV_OBJECT (user));
            }
        }
    } else if (root && root->type == YAML_MAPPING_NODE) {
        /* Support { "users": [ ... ] } */
        yaml_node_pair_t *pair;
        for (pair = root->data.mapping.pairs.start;
             pair < root->data.mapping.pairs.top; pair++) {
            yaml_node_t *k = yaml_document_get_node (&doc, pair->key);
            yaml_node_t *v = yaml_document_get_node (&doc, pair->value);
            if (!k || !v || k->type != YAML_SCALAR_NODE)
                continue;
            const char *key = (const char *)k->data.scalar.value;
            if (0 == strcmp (key, "users") && v->type == YAML_SEQUENCE_NODE) {
                yaml_node_item_t *item;
                for (item = v->data.sequence.items.start;
                     item < v->data.sequence.items.top; item++) {
                    yaml_node_t *node = yaml_document_get_node (&doc, *item);
                    if (!node || node->type != YAML_MAPPING_NODE)
                        continue;
                    char *username = NULL;
                    char *password = NULL;
                    char *iface = NULL;
                    unsigned long mark = 0;
                    yaml_node_pair_t *mpair;
                    for (mpair = node->data.mapping.pairs.start;
                         mpair < node->data.mapping.pairs.top; mpair++) {
                        yaml_node_t *mk =
                            yaml_document_get_node (&doc, mpair->key);
                        yaml_node_t *mv =
                            yaml_document_get_node (&doc, mpair->value);
                        if (!mk || !mv || mk->type != YAML_SCALAR_NODE ||
                            mv->type != YAML_SCALAR_NODE)
                            continue;
                        const char *mkey =
                            (const char *)mk->data.scalar.value;
                        const char *mval =
                            (const char *)mv->data.scalar.value;
                        if (0 == strcmp (mkey, "username"))
                            username = (char *)mval;
                        else if (0 == strcmp (mkey, "password"))
                            password = (char *)mval;
                        else if (0 == strcmp (mkey, "mark"))
                            mark = strtoul (mval, NULL, 0);
                        else if (0 == strcmp (mkey, "iface"))
                            iface = (char *)mval;
                    }
                    if (username && password) {
                        HevSocks5UserMark *user;
                        user = hev_socks5_user_mark_new (
                            username, strlen (username), password,
                            strlen (password), (unsigned int)mark);
                        if (!user)
                            continue;
                        if (iface && iface[0] != '\0')
                            user->iface = strdup (iface);
                        if (hev_socks5_authenticator_add (
                                auth, HEV_SOCKS5_USER (user)) < 0)
                            hev_object_unref (HEV_OBJECT (user));
                    }
                }
            }
        }
    }

    yaml_document_delete (&doc);
    yaml_parser_delete (&parser);
    fclose (fp);
}

static void
hev_socks5_proxy_load_file (HevSocks5Authenticator *auth, const char *file)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    FILE *fp;
    int c;

    fp = fopen (file, "r");
    if (!fp) {
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    /* Detect JSON/YAML document and delegate */
    do {
        c = fgetc (fp);
        if (c == EOF)
            break;
    } while (c == ' ' || c == '\t' || c == '\r' || c == '\n');
    if (c == '{' || c == '[') {
        fclose (fp);
        hev_socks5_proxy_load_file_yaml (auth, file);
        return;
    }
    /* Not JSON/YAML sequence, rewind and parse legacy format */
    rewind (fp);

    while ((nread = getline (&line, &len, fp)) != -1) {
        HevSocks5UserMark *user;
        unsigned int nlen;
        unsigned int plen;
        char name[256];
        char pass[256];
        long mark = 0;
        char iface[256] = { 0 };
        int res;

        /* Format: USER PASS [MARK] [SRC_IP] [IFACE]
         * We keep backward compatibility. We parse up to 5 tokens, but only
         * the 1st two are mandatory. MARK remains hexadecimal; IFACE is
         * optional here to bind to device.
         */
        res = sscanf (line, "%255s %255s %lx %*255s %255s\n", name, pass, &mark, iface);
        if (res < 2) {
            /* Try legacy 3-field form */
            res = sscanf (line, "%255s %255s %lx\n", name, pass, &mark);
        }
        if (res < 2) {
            LOG_E ("socks5 proxy user/pass format");
            continue;
        }

        nlen = strlen (name);
        plen = strlen (pass);
        user = hev_socks5_user_mark_new (name, nlen, pass, plen, mark);
        if (!user) {
            LOG_E ("socks5 proxy user new");
            continue;
        }
        if (iface[0] != '\0') {
            user->iface = strdup (iface);
        }
        res = hev_socks5_authenticator_add (auth, HEV_SOCKS5_USER (user));
        if (res < 0) {
            LOG_E ("socks5 proxy user conflict");
            hev_object_unref (HEV_OBJECT (user));
        }
    }

    free (line);
    fclose (fp);
}

static void
hev_socks5_proxy_load (void)
{
    HevSocks5Authenticator *auth;
    const char *file, *name, *pass;
    int i;

    LOG_D ("socks5 proxy load");

    file = hev_config_get_auth_file ();
    name = hev_config_get_auth_username ();
    pass = hev_config_get_auth_password ();

    if (!file && !name && !pass)
        return;

    auth = hev_socks5_authenticator_new ();
    if (!auth)
        return;

    if (file) {
        hev_socks5_proxy_load_file (auth, file);
    } else {
        HevSocks5UserMark *user;

        user = hev_socks5_user_mark_new (name, strlen (name), pass,
                                         strlen (pass), 0);
        if (user)
            hev_socks5_authenticator_add (auth, HEV_SOCKS5_USER (user));
    }

    for (i = 0; i < workers; i++) {
        HevSocks5Worker *worker;

        worker = worker_list[i];
        hev_socks5_worker_set_auth (worker, auth);
        hev_socks5_worker_reload (worker);
    }

    hev_object_unref (HEV_OBJECT (auth));
}

static void
sigint_handler (int signum)
{
    hev_socks5_proxy_load ();
}

int
hev_socks5_proxy_init (void)
{
    LOG_D ("socks5 proxy init");

    if (hev_task_system_init () < 0) {
        LOG_E ("socks5 proxy task system");
        goto exit;
    }

    task = hev_task_new (-1);
    if (!task) {
        LOG_E ("socks5 proxy task");
        goto exit;
    }

    workers = hev_config_get_workers ();
    work_threads = hev_malloc0 (sizeof (pthread_t) * workers);
    if (!work_threads) {
        LOG_E ("socks5 proxy work threads");
        goto exit;
    }

    worker_list = hev_malloc0 (sizeof (HevSocks5Worker *) * workers);
    if (!worker_list) {
        LOG_E ("socks5 proxy worker list");
        goto exit;
    }

    factory = hev_socket_factory_new (hev_config_get_listen_address (),
                                      hev_config_get_listen_port (),
                                      hev_config_get_listen_ipv6_only ());
    if (!factory) {
        LOG_E ("socks5 proxy socket factory");
        goto exit;
    }

    signal (SIGPIPE, SIG_IGN);
    signal (SIGUSR1, sigint_handler);

    return 0;

exit:
    hev_socks5_proxy_fini ();
    return -1;
}

void
hev_socks5_proxy_fini (void)
{
    LOG_D ("socks5 proxy fini");

    if (task)
        hev_task_unref (task);
    if (work_threads)
        hev_free (work_threads);
    if (worker_list)
        hev_free (worker_list);
    if (factory)
        hev_socket_factory_destroy (factory);
    hev_task_system_fini ();
}

static void *
work_thread_handler (void *data)
{
    HevSocks5Worker **worker = data;
    int res;
    int fd;

    if (hev_task_system_init () < 0) {
        LOG_E ("socks5 proxy worker task system");
        goto exit;
    }

    fd = hev_socket_factory_get (factory);
    if (fd < 0) {
        LOG_E ("socks5 proxy worker socket");
        goto free;
    }

    res = hev_socks5_worker_init (*worker, fd);
    if (res < 0) {
        LOG_E ("socks5 proxy worker init");
        goto free;
    }

    hev_socks5_worker_start (*worker);

    hev_task_system_run ();

    hev_socks5_worker_destroy (*worker);
    *worker = NULL;

free:
    if (fd >= 0)
        close (fd);
    hev_task_system_fini ();
exit:
    return NULL;
}

static void
hev_socks5_proxy_task_entry (void *data)
{
    int res;
    int i;

    LOG_D ("socks5 proxy task run");

    listen_fd = hev_socket_factory_get (factory);
    if (listen_fd < 0)
        return;

    worker_list[0] = hev_socks5_worker_new ();
    if (!worker_list[0]) {
        LOG_E ("socks5 proxy worker");
        return;
    }

    res = hev_socks5_worker_init (worker_list[0], listen_fd);
    if (res < 0) {
        LOG_E ("socks5 proxy worker init");
        return;
    }

    hev_socks5_worker_start (worker_list[0]);

    for (i = 1; i < workers; i++) {
        worker_list[i] = hev_socks5_worker_new ();
        if (!worker_list[i]) {
            LOG_E ("socks5 proxy worker");
            return;
        }

        pthread_create (&work_threads[i], NULL, work_thread_handler,
                        &worker_list[i]);
    }

    hev_socks5_proxy_load ();

    task = NULL;
}

void
hev_socks5_proxy_run (void)
{
    LOG_D ("socks5 proxy run");

    hev_task_run (task, hev_socks5_proxy_task_entry, NULL);

    hev_task_system_run ();

    if (listen_fd >= 0)
        close (listen_fd);

    if (worker_list[0]) {
        int i;

        for (i = 1; i < workers; i++)
            pthread_join (work_threads[i], NULL);

        hev_socks5_worker_destroy (worker_list[0]);
        worker_list[0] = NULL;
    }
}

void
hev_socks5_proxy_stop (void)
{
    int i;

    for (i = 0; i < workers; i++) {
        HevSocks5Worker *worker;

        worker = worker_list[i];
        if (!worker)
            continue;

        hev_socks5_worker_stop (worker);
    }
}
