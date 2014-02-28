UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
LDLIBS += -lcrypto
endif

CFLAGS += -g -O3 -std=c99

objects = hash.o main.o tests.o sslKeyExchange.o

hash: $(objects)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) -c -o $*.o $(CPPFLAGS) $(CFLAGS) $*.c

.PHONY: clean
clean:
	rm -f $(objects) hash $(deps)

.PHONY: all
all: hash

