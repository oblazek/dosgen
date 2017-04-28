CC=gcc
CFLAGS=-g -Wall -Werror#-O1 
LIBS=-L. -ldos -ltrafgen -lnl-3 -lnl-genl-3 -lnl-3 -ltcpgen -lpcap -lm -lpthread -z muldefs

all: libdos.a libtcpgen.a dosgen 

# DoSgen
dosgen:  libdos.a libtcpgen.a dosgen.c
	$(CC) $(CFLAGS) -o $@ dosgen.c $(LIBS)

# Library
libdos.a: trafgen_wrapper.o
	ar rcs -o $@ $^

trafgen_wrapper.o: trafgen_wrapper.c trafgen_wrapper.h trafgen_configs.h libtrafgen.a 
	$(CC) $(CFLAGS) --static -c -o $@ trafgen_wrapper.c

libtrafgen.a:
	(cd trafgen; make trafgen && cp libtrafgen.a ../)

libtcpgen.a:
	(cd raw; $(CC) $(CFLAGS) -c tcpgen.c handshake.c checksum.c; ar rcs -o libtcpgen.a tcpgen.o handshake.o checksum.o; cp libtcpgen.a ../)

clean:
	rm *.o
	rm *.a
	rm ./dosgen
	rm raw/*.[oa]
