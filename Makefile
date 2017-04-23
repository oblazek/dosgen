CC=gcc
CFLAGS=-g
LIBS=-L. -ldos -ltrafgen -lnl-3 -lnl-genl-3 -lnl-3 -ltcpgen -larping -lpcap -lm -lpthread -z muldefs

all: libdos.a libarping.a libtcpgen.a dosgen 

# DoSgen
dosgen:  libdos.a dosgen.c
	$(CC) $(CFLAGS) -o $@ dosgen.c $(LIBS)

# Library
libdos.a: trafgen_wrapper.o
	ar rcs -o $@ $^

trafgen_wrapper.o: trafgen_wrapper.c trafgen_wrapper.h trafgen_configs.h libtrafgen.a 
	$(CC) $(CFLAGS) --static -c -o $@ trafgen_wrapper.c

libtrafgen.a:
	(cd trafgen; make trafgen && cp libtrafgen.a ../)

libarping.a:
	(cd arping; gcc -c arping.c; ar rcs -o libarping.a arping.o; cp libarping.a ../)

libtcpgen.a:
	(cd raw; gcc -c main.c handshake.c checksum.c; ar rcs -o libtcpgen.a main.o handshake.o checksum.o; cp libtcpgen.a ../)

clean:
	rm *.o
	rm *.a
	rm ./dosgen
	rm arping/*.[oa]
	rm raw/*.[oa]
