CC = gcc -std=gnu99
#WARN_FLAGS = -Wall -Wextra -Werror

CFLAGS += -fPIC
# WARNING OPTIONS
# turn on typical warnings
CFLAGS += -Wall
CFLAGS += -Wextra
# turn warnings into errors
CFLAGS += -Werror

# suppress warnings for a couple of things
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-missing-field-initializers
CFLAGS += -Wno-missing-braces

#CFLAGS += -fsanitize=address
CFLAGS += -fno-strict-aliasing
#CFLAGS += -fstack-protector-all

# TODO: re-enable this after some things are fixed, like SecurityKeys.h
CFLAGS += -Wno-ignored-qualifiers

# yet more warnings from https://news.ycombinator.com/item?id=7371806
CFLAGS += -Wformat=2
CFLAGS += -D_FORTIFY_SOURCE=2

FEATURES = splitdebug            
DEBUG_FLAGS = -g3 -ggdb3 -O2
DEFINES = 

WOLFLIBS = -I ./ -I/usr/local/include/wolfssl -I/usr/local/include/curl \
           -L/usr/local/lib -L/usr/local/include/wolfssl/wolfcrypt \
           -L/usr/local/include/wolfssl 
WOLFLIBS += -lcurl -lwolfssl
WOLFLIBS += -no-pie 

OPENLIBS = -I ./ -I/usr/local/include/curl -L/usr/local/lib 
OPENLIBS = -lcrypto -lcurl

# The following TSSLIBS definition is for the Raspberry Pi
RPI_TSSLIBS = -L/usr/lib/arm-linux-gnueabihf/engines-1.1/ -ltpm2tss
# The following TSSLIBS definition is for a linux machine
TSSLIBS = -ltpm2tss -L/usr/lib/x86_64-linux-gnu/engines-1.1/

vpath %.c ./ ./lib ./wolfssl_wrapper ./DRCode
SRC := $(wildcard *.c) \
       $(wildcard lib/*.c) \
       $(wildcard wolfssl_wrapper/*.c) 
OBJS = $(SRC:%.c=%.o)

OSRC := $(wildcard *.c) \
        $(wildcard lib/*.c) \
        $(wildcard openssl_wrapper/*.c)
OOBJ = $(OSRC:%.c=%.o)

wolftest: DEFINES += -D __WOLF_SSL__ -D __KEYFACTOR_LOCAL_TESTING__ -D _DEBUG
wolftest: ${OBJS}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${WOLFLIBS}

opentest: DEFINES += -D __OPEN_SSL__ -D __KEYFACTOR_LOCAL_TESTING__ -D _DEBUG
opentest: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS}

rpi9670test: DEFINES += -D __OPEN_SSL__ -D __KEYFACTOR_LOCAL_TESTING__ -D _DEBUG -D __TPM__
rpi9670test: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS} ${RPI_TSSLIBS}

test: rpi9670test

# define the builds
%.o: %.c
	$(info building $@ from $<)
	- @${CC} ${DEFINES} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c -o $@ $<

# define the clean or delete commands
.PHONY: deleteallobs
deleteallobs:
	rm -rf ${OBJS} ${OOBJ} agent

.PHONY: cleanall
cleanall: deleteallobs

.PHONY: clean
clean: deleteallobs
