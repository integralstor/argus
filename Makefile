CC = gcc
CFLAGS = -g -O3 \
	 -I./ \
	 $(shell pkg-config --cflags glib-2.0)

LDFLAGS = $(shell pkg-config --libs glib-2.0) -lrt

PROG = argus
HDRS = argus.h
SRCS = argus.c

OBJS = $(SRCS:.c=.o)

all : clean $(PROG)

$(PROG) : $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(PROG)

argus.o : argus.c argus.h

clean :
	rm -f core $(PROG) $(OBJS)

uninstall :
	rm -f $(DESTDIR)/usr/bin/argus

install : uninstall
	mkdir -p $(DESTDIR)/usr/bin
	install -m 0755 argus $(DESTDIR)/usr/bin/argus
