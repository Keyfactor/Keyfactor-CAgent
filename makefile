# ---------------------------------------------------------------------------
# Build configuration
#
# Variant is selected via two variables; callers usually go through the
# legacy target aliases at the bottom of this file.
#
#   CRYPTO = wolfssl | openssl          (default: wolfssl)
#   OUT    = exec    | lib              (default: exec)
#
# Optional flavors (set to any non-empty value, e.g. pi=1):
#   qa   -> defines __QATESTING__
#   pi   -> adds -Wno-format and selects Pi engine paths when tpm is on
#   tpm  -> defines __TPM__ and links -ltpm2tss
# ---------------------------------------------------------------------------

CC          ?= gcc
CSTD        ?= -std=gnu99
CRYPTO      ?= wolfssl
OUT         ?= exec
DEBUG_FLAGS ?= -g0 -O0

BUILD_DIR := build/$(CRYPTO)-$(OUT)

# ---- Global flags (standard make variables) ----
CPPFLAGS += -I. -D_POSIX_C_SOURCE=200809L -D__RUN_CHAIN_JOBS__

CFLAGS += $(CSTD) -fPIC \
          -Wall -Wextra -Wvla -Wshadow -Werror -pedantic \
          -fno-strict-aliasing \
          -Wno-unused-parameter -Wno-missing-field-initializers \
          -Wno-missing-braces -Wno-unused-variable \
          -Wno-unused-but-set-variable -Wno-unused-label \
          -Wno-unused-function -Wno-pointer-sign \
          -Wno-deprecated-declarations -Wno-ignored-qualifiers \
          -MMD -MP \
          $(DEBUG_FLAGS)

LDFLAGS +=
LDLIBS  +=

# ---- Per-crypto configuration ----
ifeq ($(CRYPTO),wolfssl)
  CPPFLAGS    += -D__WOLF_SSL__ -D_XOPEN_SOURCE=600 \
                 -I/usr/local/include/wolfssl -I/usr/local/include/curl
  LDFLAGS     += -L/usr/local/lib -no-pie
  LDLIBS      += -lcurl -lwolfssl
  WRAPPER_SRC := $(wildcard wolfssl_wrapper/*.c)
else ifeq ($(CRYPTO),openssl)
  CPPFLAGS    += -D__OPEN_SSL__ -I/usr/local/include/curl
  LDFLAGS     += -L/usr/local/lib
  LDLIBS      += -lcrypto -lcurl
  WRAPPER_SRC := $(wildcard openssl_wrapper/*.c)
else
  $(error CRYPTO must be 'wolfssl' or 'openssl', got '$(CRYPTO)')
endif

# ---- Output type ----
ifeq ($(OUT),lib)
  CPPFLAGS += -D__MAKE_LIBRARY__
  LDFLAGS  += -shared
  ARTIFACT := libagent.so
else ifeq ($(OUT),exec)
  ARTIFACT := agent
else
  $(error OUT must be 'exec' or 'lib', got '$(OUT)')
endif

# ---- Optional flavors ----
ifdef qa
  CPPFLAGS += -D__QATESTING__
endif

ifdef pi
  CFLAGS += -Wno-format
endif

ifdef tpm
  CPPFLAGS += -D__TPM__
  LDLIBS   += -ltpm2tss
  ifdef pi
    LDFLAGS += -L/usr/lib/arm-linux-gnueabihf/engines-1.1/ \
               -L/usr/lib/arm-linux-gnueabihf/engines-3/
  else
    LDFLAGS += -L/usr/lib/x86_64-linux-gnu/engines-1.1/
  endif
endif

# ---- Sources / objects / deps ----
SRC  := $(wildcard *.c) $(wildcard lib/*.c) $(WRAPPER_SRC)
OBJS := $(SRC:%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

# ---- Rules ----
.PHONY: all clean install
all: $(ARTIFACT)

$(ARTIFACT): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(info building $@ from $<)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

-include $(DEPS)

clean:
	rm -rf build agent libagent.so

install: $(ARTIFACT)
ifneq ($(OUT),lib)
	$(error 'install' requires OUT=lib; try 'make wolfinstall' or 'make openinstall')
endif
	sudo install -m 0755 libagent.so /usr/lib/libagent.so

# ---------------------------------------------------------------------------
# Legacy target aliases — preserve existing muscle memory and CI contracts.
# ---------------------------------------------------------------------------
.PHONY: wolftest wolflib wolfpi wolfinstall \
        opentest openlib openpi openinstall \
        qatesting qawolftesting rpi9670test \
        cleanall deleteallobs

wolftest:      ; $(MAKE) CRYPTO=wolfssl OUT=exec
wolflib:       ; $(MAKE) CRYPTO=wolfssl OUT=lib
wolfpi:        ; $(MAKE) CRYPTO=wolfssl OUT=exec pi=1
wolfinstall:   ; $(MAKE) CRYPTO=wolfssl OUT=lib install

opentest:      ; $(MAKE) CRYPTO=openssl OUT=exec
openlib:       ; $(MAKE) CRYPTO=openssl OUT=lib
openpi:        ; $(MAKE) CRYPTO=openssl OUT=exec pi=1
openinstall:   ; $(MAKE) CRYPTO=openssl OUT=lib install

qatesting:     ; $(MAKE) CRYPTO=openssl OUT=exec qa=1
qawolftesting: ; $(MAKE) CRYPTO=wolfssl OUT=exec qa=1
rpi9670test:   ; $(MAKE) CRYPTO=openssl OUT=exec pi=1 tpm=1

cleanall deleteallobs: clean
