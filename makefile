CC = gcc -std=gnu99
#WARN_FLAGS = -Wall -Wextra -Werror

CFLAGS += -fPIC
# WARNING OPTIONS
# turn on typical warnings
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wvla
CFLAGS += -Wshadow
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
CFLAGS += -Wno-deprecated-declarations

CFLAGS += -fno-strict-aliasing
CFLAGS += -Wno-ignored-qualifiers
CFLAGS += -pedantic
          
DEBUG_FLAGS = -g0 -O0
DEFINES = 
DEFINES += -D__RUN_CHAIN_JOBS__
DEFINES += -D_POSIX_C_SOURCE=200809L

WOLFLIBS = -I ./ -I/usr/local/include/wolfssl -I/usr/local/include/curl \
           -L/usr/local/lib -L/usr/local/include/wolfssl/wolfcrypt \
           -L/usr/local/include/wolfssl 
WOLFLIBS += -lcurl -lwolfssl
WOLFLIBS += -no-pie 

OPENLIBS = -I ./ -I/usr/local/include/curl -L/usr/local/lib 
OPENLIBS = -lcrypto -lcurl

# TPM specific variables for the tpm2tss stack
# The following TSSLIBS definition is for the Raspberry Pi
RPI_TSSLIBS = -L/usr/lib/arm-linux-gnueabihf/engines-1.1/ -L/usr/lib/arm-linux-gnueabihf/engines-3/ -ltpm2tss
# The following TSSLIBS definition is for a linux machine
TSSLIBS = -ltpm2tss -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -L/usr/lib/arm-linux-gnueabihf/engines-3/

vpath %.c ./ ./lib ./wolfssl_wrapper
SRC := $(wildcard *.c) \
       $(wildcard lib/*.c) \
       $(wildcard wolfssl_wrapper/*.c) 
OBJS = $(SRC:%.c=%.o)

OSRC := $(wildcard *.c) \
        $(wildcard lib/*.c) \
        $(wildcard openssl_wrapper/*.c)
OOBJ = $(OSRC:%.c=%.o)

# The base wolf build for a 64-bit os
wolftest: DEFINES += -D__WOLF_SSL__ -D_XOPEN_SOURCE=600
wolftest: ${OBJS}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${WOLFLIBS}

# The base wolfSSL build to create a shared library
wolflib: DEFINES += -D__WOLF_SSL__ -D__MAKE_LIBRARY__  -D_XOPEN_SOURCE=600
wolflib: ${OBJS}
	${CC} -shared ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o libagent.so $^ ${WOLFLIBS}

# How to install the shared library
wolfinstall: libagent.so
	sudo cp libagent.so /usr/lib
	sudo chmod 755 /usr/lib/libagent.so

# The wolfSSL build for any 32-bit OS like RaspOS
wolfpi: DEFINES += -D__WOLF_SSL__ -Wno-format  -D_XOPEN_SOURCE=600
wolfpi: ${OBJS}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${WOLFLIBS}

# The base openSSL build for a 64-bit OS
opentest: DEFINES += -D__OPEN_SSL__
opentest: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS}

# The base openSSL build to create a shared library
openlib: DEFINES += -D__OPEN_SSL__ -D__MAKE_LIBRARY__
openlib: ${OOBJ}
	${CC} -shared ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o libagent.so $^ ${OPENLIBS}

# The openSSL build for any 32-bit OS like RaspOS
openpi: DEFINES += -D__OPEN_SSL__ -Wno-format
openpi: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS}

# How to install the shared library
openinstall: libagent.so
	sudo cp libagent.so /usr/lib
	sudo chmod 755 /usr/lib/libagent.so

qatesting: DEFINES += -D__OPEN_SSL__ -D__QATESTING__
qatesting: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS}

qawolftesting: DEFINES += -D__WOLF_SSL__ -D_XOPEN_SOURCE=600 -D__QATESTING__
qawolftesting: ${OBJS}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${WOLFLIBS}

# The base build for a Raspberry Pi with a TPM installed
rpi9670test: DEFINES += -D__OPEN_SSL__ -D__TPM__ -Wno-format
rpi9670test: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o agent $^ ${OPENLIBS} ${RPI_TSSLIBS}

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
