CC = gcc

ifeq ($(CC),clang)
  STACK_FLAGS = -fno-stack-protector -Wl,-allow_stack_execute
else
  STACK_FLAGS = -fno-stack-protector -z execstack
endif

CFLAGS = ${STACK_FLAGS} -Wall -Iutil -Iatm -Ibank -Irouter -I. -I/usr/include/openssl

OPENSSL_FLAGS = -lssl -lcrypto


all: bin bin/init bin/atm bin/bank bin/router

bin:
	mkdir -p bin

# @Jacob moved bin/init target here
bin/init : init.c
	${CC} ${CFLAGS} init.c -o bin/init $(OPENSSL_FLAGS)

bin/atm : atm/atm-main.c atm/atm.c protocol.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c protocol.c -o bin/atm $(OPENSSL_FLAGS)

bin/bank : bank/bank-main.c bank/bank.c protocol.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c protocol.c -o bin/bank $(OPENSSL_FLAGS)

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

# @Jacob Improved cleaning targets
clean: clean-bin clean-test
	@echo "Cleaned all binaries and test artifacts"
	
clean-bin:
	rm -rf bin

# @ArminRezz Clean test artifacts (card files, init files)
clean-test:
	rm -f *.card /tmp/test.*
