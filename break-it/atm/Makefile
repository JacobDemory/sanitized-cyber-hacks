CC = gcc

ifeq ($(CC),clang)
  STACK_FLAGS = -fno-stack-protector -Wl,-allow_stack_execute
else
  STACK_FLAGS = -fno-stack-protector -z execstack
endif

CFLAGS = ${STACK_FLAGS} -g -Wall -Iutil -Iatm -Ibank -Irouter -I.
LIBS = -lcrypto

all: bin bin/atm bin/bank bin/router bin/init

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c util/list.c util/util.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c util/list.c util/util.c ${LIBS} -o bin/atm

bin/bank : bank/bank-main.c bank/bank.c util/list.c util/util.c
	${CC} ${CFLAGS} bank/bank.c util/list.c util/util.c bank/bank-main.c ${LIBS} -o bin/bank

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c ${LIBS} -o bin/router

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c ${LIBS} -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c ${LIBS} -o bin/hash-table-test

bin/init: init.c util/util.c
	${CC} ${CFLAGS} init.c util/util.c ${LIBS} -o bin/init

clean:
	cd bin && rm -f *
