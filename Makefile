CC := gcc
CFLAGS := -Wall -g -c
LDFLAGS := -lpopt -lssh2 -lnetfilter_queue -lpthread
SRCDIR := src
SOURCES := $(SRCDIR)/ssh.c $(SRCDIR)/tcp.c $(SRCDIR)/udp.c \
	$(SRCDIR)/dns.c $(SRCDIR)/netfilter.c $(SRCDIR)/main.c
OBJECTS := $(SOURCES:.c=.o)
EXECUTABLE := debind

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean::
	rm -f src/*.o $(EXECUTABLE)
