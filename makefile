CC = gcc
WARN_FLAGS = -Wall -Wno-cpp -Wno-implicit-function-declaration -Wno-char-subscripts -Wno-int-conversion -Wno-unused-result  
DEBUG_FLAGS = -g3 -ggdb
C_STD = -std=gnu99
# The following LIBS uses a custom curl build
# LIBS = -lcrypto -L/home/pi/FTP/files/curl/lib/.libs -lcurl
# Use the following LIBS for a standard curl build
LIBS = -lcrypto -lcurl
# The following TSSLIBS definition is for the Raspberry Pi
RPI_TSSLIBS = -L/usr/lib/arm-linux-gnueabihf/engines-1.1/ -ltpm2tss
# The following TSSLIBS definition is for a linux machine
TSSLIBS = -ltpm2tss -L/usr/lib/x86_64-linux-gnu/engines-1.1/
DEFINES = 
TESTLIBS = -lcrypto
ENGINETESTLIBS = -L/usr/lib/arm-linux-gnueabihf/engines-1.1/ -lcrypto -ltpm2tss
ENGINETESTOBS = engine-test.o logging.o base64.o
COMMONOBS =  logging.o utils.o base64.o
RPIOBS = rpi_gpio.o
JSONOBS = json.o csr.o
RELEASEOBS = agent.o httpclient.o dto.o inventory.o management.o schedule.o \
             enrollment.o config.o encryption.o session.o serialize.o fetchlogs.o
VERIFYOBS = verify.o verify_test.o
ENCRYPTIONTESTOBS = encryption.o encryption_test.o
ENCRYPTIONTESTSTANDALONEOBS = encryption.o encryption_standalone.o
SYMMETRICTESTOBS = symmetricEncryption.o symmetric_test.o
SYMMETRICSTANDALONEOBS = symmetricEncryption.o symmetric_standalone.o
SELFSIGNEDOBS = generate_selfsigned.o config.o
ECDHTESTOBS = ecdh_test.o ecdh.o symmetricEncryption.o
SUCCESS = echo "*** Build completed successfully ***"; \
		  echo " ";
FAILURE = echo "*** Build FAILED ***"; \
		  echo " ";

WOLFLIBS = -I/usr/local/include/wolfssl -I/usr/local/include/curl -L/usr/local/lib -lcurl -lwolfssl
WOLF = agent.c session.c csr.c lib/json.c httpclient.c lib/base64.c dto.c inventory.c management.c utils.c schedule.c enrollment.c logging.c config.c serialize.c fetchlogs.c

release: ${RELEASEOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o agent $^ ${LIBS}; then\
		${SUCCESS} \
	else \
		${FAILURE} \
	fi

rpirelease: DEFINE += -D __RPI__
rpirelease: ${RELEASEOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o agent $^ ${LIBS}; then\
		${SUCCESS} \
	else \
		${FAILURE} \
	fi

rpitpmrelease: DEFINES += -D __TPM__ -D __RPI__
rpitpmrelease: ${RELEASEOBS} ${JSONOBS} ${COMMONOBS} ${RPIOBS}
	@if ${CC} -o agent $^ ${LIBS} ${RPI_TSSLIBS}; then\
		${SUCCESS} \
	else \
		${FAILURE} \
	fi

tpm: rpitpmrelease
rpi: rpirelease

engine-test: ${ENGINETESTOBS}
	@if ${CC} -o $@ $^ ${ENGINETESTLIBS}; then\
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


verify_test: ${VERIFYOBS} ${COMMONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS}; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


encryption_test: ${ENCRYPTIONTESTOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS}; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


encryption_standalone: ${ENCRYPTIONTESTSTANDALONEOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS}; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


symmetric_test: ${SYMMETRICTESTOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS}; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


symmetric_standalone: ${SYMMETRICSTANDALONEOBS} ${JSONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS}; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


generate_selfsigned: ${SELFSIGNEDOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS} &> err.log; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


ecdh_test: ${ECDHTESTOBS} ${JSONOBS} ${COMMONOBS}
	@if ${CC} -o $@ $^ ${TESTLIBS}; then \
		${SUCCESS} \
	else \
		${FAILURE} \
	fi


# only define those builds where the path is different from the build location

json.o: lib/json.c
	$(info compiling $^)
	- @${CC} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c $^

base64.o: lib/base64.c
	$(info compiling $^)
	- @${CC} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c $^

# now define the generic builds
%.o: %.c
	$(info compiling $^)
	- @${CC} ${DEFINES} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c $^

# define the clean or delete commands
.PHONY: deleteallobs
deleteallobs:
	$(info deleting all object files)
	@for i in *.o; do \
		if [ -f $$i ]; then $(info deleting intermediate object files) rm $$i; fi; \
	done;
	$(info deleting executable files)
	@if [ -f agent ]; then rm agent; fi;
	@if [ -f verify_test ]; then rm verify_test; fi;
	@if [ -f encryption_test ]; then rm encryption_test; fi;
	@if [ -f symmetric_test ]; then rm symmetric_test; fi;
	@if [ -f symmetric_standalone ]; then rm symmetric_standalone; fi;
	@if [ -f generate_selfsigned ]; then rm generate_selfsigned; fi;
	@if [ -f ecdh_test ]; then rm ecdh_test; fi;
	@if [ -f engine-test ]; then rm engine-test; fi;
	$(info *** All objects removed successfully ***)

cleanall: deleteallobs
	
clean: deleteallobs


