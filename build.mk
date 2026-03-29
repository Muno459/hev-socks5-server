# Build

rwildcard=$(foreach d,$(wildcard $1*), \
          $(call rwildcard,$d/,$2) \
          $(filter $(subst *,%,$2),$d))

SRCFILES=$(call rwildcard,$(SRCDIR)/,*.c *.S)
# Exclude kernel module sources (compiled separately)
SRCFILES:=$(filter-out %/hev-tcpfp-kmod.c %/hev-tcpfp.mod.c,$(SRCFILES))

# Auto-enable DKMS if kernel headers exist
KMOD_AVAIL := $(wildcard /lib/modules/$(shell uname -r)/build/Makefile)
ifneq ($(KMOD_AVAIL),)
  ENABLE_DKMS := 1
endif

ifneq ($(ENABLE_DKMS),1)
SRCFILES:=$(filter-out %/hev-dkms-fingerprint.c,$(SRCFILES))
endif

ifeq ($(REV_ID),)
  ifneq (,$(wildcard .rev-id))
    REV_ID=$(shell cat .rev-id)
  endif
  ifeq ($(REV_ID),)
    REV_ID=$(shell git -C $(SRCDIR) rev-parse --short HEAD)
  endif
  ifeq ($(REV_ID),)
    REV_ID=unknown
  endif
endif
VERSION_CFLAGS=-DCOMMIT_ID=\"$(REV_ID)\"
