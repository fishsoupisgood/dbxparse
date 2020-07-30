LIBS=$(shell pkg-config --libs openssl)
CFLAGS=$(shell pkg-config --cflags openssl) -I/usr/include/efi -I/usr/include/efi/x64 -I/usr/include/efi/x86_64

dbxparse:dbxparse.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $< ${LIBS}
