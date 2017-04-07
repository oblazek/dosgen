#!/bin/bash

gcc -c ../arping/arping.c
ar rcs ./libarping.a ../arping/arping.o
qmake
make

