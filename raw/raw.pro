TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -L$$PWD/ -larping -lpcap -lpthread

SOURCES += main.c \
    handshake.c \
    checksum.c

HEADERS += \
    handshake.h \
    checksum.h
