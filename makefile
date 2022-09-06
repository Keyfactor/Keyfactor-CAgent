CC = gcc -std=gnu99
#WARN_FLAGS = -Wall -Wextra -Werror

CFLAGS += -fPIC
# WARNING OPTIONS
# turn on typical warnings
CFLAGS += -Wall
CFLAGS += -Wextra
# turn warnings into errors
CFLAGS += -Werror

# suppress warnings for some things
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-missing-field-initializers
CFLAGS += -Wno-missing-braces
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-unused-but-set-variable
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-pointer-sign

CFLAGS += -fno-strict-aliasing
CFLAGS += -Wno-ignored-qualifiers
          
DEBUG_FLAGS = -g0 -O0
DEFINES = 
#DEFINES += -D__RUN_CHAIN_JOBS__
#DEFINES += -D__INFINITE_AGENT__

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

wolftest: DEFINES += -D__WOLF_SSL__
wolftest: ${OBJS}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${WOLFLIBS}

opentest: DEFINES += -D__OPEN_SSL__
opentest: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS}

openlib: DEFINES += -D__OPEN_SSL__
openlib: ${OOBJ}
	${CC} -shared ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o libagent.so $^ ${OPENLIBS}

openinstall: libagent.so
	sudo cp libagent.so /usr/lib
	sudo chmod 755 /usr/lib/libagent.so

rpi9670test: DEFINES += -D__OPEN_SSL__ -D__TPM__
rpi9670test: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS} ${RPI_TSSLIBS}

test: wolftest

# define the builds
%.o: %.c
	$(info building $@ from $<)
	- @${CC} ${CFLAGS} ${DEFINES} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c -o $@ $<

# define the clean or delete commands
.PHONY: deleteallobs
deleteallobs:
	rm -rf ${OBJS} ${OOBJ} agent

.PHONY: cleanall
cleanall: deleteallobs

.PHONY: clean
clean: deleteallobs
