bin = uhvm
ver = 0.3
src = uhvm.c
inc = -I/usr/include -I/usr/include/hal

DESTDIR?=
ETCDIR?=/etc
PREFIX?=/usr
dst = ${DESTDIR}${PREFIX}
etc = ${DESTDIR}${ETCDIR}

CC = gcc
CFLAGS += -Wall -Wextra -std=gnu99 -Wformat-security -Wshadow \
			 -Wpointer-arith -ggdb \
			 $(shell pkg-config --cflags glib-2.0 dbus-glib-1)
LDFLAGS += -lhal -lhal-storage $(shell pkg-config --libs glib-2.0 dbus-glib-1)

all: $(bin)

%: %.c 
	$(CC) -ggdb -o $(bin) $(src) $(inc) $(CFLAGS) $(LDFLAGS)

clean:
	@rm -rf $(bin) uhvm-$(ver).tar.bz2

dist: clean
	@mkdir -p uhvm-$(ver)
	@cp -R AUTHORS ChangeLog PKGBUILD README uhvm.1 $(src) \
		LICENSE HACKING format.sh .astylerc Makefile TODO init uhvm-$(ver)
	@tar -cf uhvm-$(ver).tar uhvm-$(ver)
	@bzip2 uhvm-$(ver).tar
	@rm -rf uhvm-$(ver)

install: all
	@echo installing executable file to $(dst)/bin
	@cp -f $(bin) $(dst)/bin
	@chmod 755 $(dst)/bin/$(bin)
	@echo installing init script to $(etc)/rc.d
	@mkdir -p $(etc)/rc.d
	@cp -f init/$(bin) $(etc)/rc.d
	@chmod 755 $(etc)/rc.d/$(bin)
	@echo making hooks directory
	@mkdir -p /etc/${bin}/hooks

uninstall:
	@echo removing /usr/bin/$(bin)
	@rm -f $(dst)/bin/$(bin)
	@echo removing $(etc)/rc.d/$(bin)
	@rm -f $(etc)/rc.d/$(bin)
	@rm -f $(dst)/share/man/man1/uhvm.1

.PHONY: all clean dist install uninstall
