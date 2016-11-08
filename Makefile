CC=gcc
CFLAGS=-g
LIBS=-L. -ldos -ltrafgen -lnl-3 -lnl-genl-3 -lnl-3 -lm -pthread -z muldefs

all: libdos.a dosgen


# Library
libdos.a: trafgen_wrapper.o
	ar rcs -o $@ $^

trafgen_wrapper.o: trafgen_wrapper.c trafgen_wrapper.h trafgen_configs.h libtrafgen.a
	$(CC) $(CFLAGS) --static -c -o $@ trafgen_wrapper.c

libtrafgen.a:
	(cd trafgen; make trafgen && cp libtrafgen.a ../)


# DoSgen
dosgen: libdos.a dosgen.c
	
	$(CC) $(CFLAGS) -o $@ dosgen.c $(LIBS)
				#--static

clean:
	rm *.o
	rm *.a


