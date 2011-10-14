CC := gcc
CFLAGS := -Wall -g
LDFLAGS := -lpopt -lssh2 -lnetfilter_queue -lpthread
NAME := debind

all::
	$(CC) ssh.c -o ssh.o -c $(CFLAGS)
	$(CC) tcp.c -o tcp.o -c $(CFLAGS)
	$(CC) udp.c -o udp.o -c $(CFLAGS)
	$(CC) dns.c -o dns.o -c $(CFLAGS)
	$(CC) netfilter.c -o netfilter.o -c $(CFLAGS)
	$(CC) main.c ssh.o dns.o tcp.o udp.o netfilter.o $(CFLAGS) $(LDFLAGS) -o $(NAME)

clean::
	rm -f *.o $(NAME)
