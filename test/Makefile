CC=gcc
CFLAGS=-Wall -g

default:
	$(CC) $(CFLAGS) server.c -o server
	$(CC) $(CFLAGS) example.c -o example
	$(CC) $(CFLAGS) client.c -o client

clean:
	rm *.o server example client