CC=gcc
CFLAGS=-Wall -O2

tap_pingd: main.o utils.o
	$(CC) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o tap_pingd
