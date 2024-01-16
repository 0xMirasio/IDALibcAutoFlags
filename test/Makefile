CC=gcc
CFLAGS=-Wall -g

default:
	$(CC) $(CFLAGS) server.c -o server.bin
	$(CC) $(CFLAGS) example.c -o example.bin
	$(CC) $(CFLAGS) client.c -o client.bin

clean:
	rm *.o *.bin