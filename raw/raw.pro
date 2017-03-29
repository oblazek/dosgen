TEMPLATE = app
CONFIG += console thread
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.c \
    handshake.c \
    checksum.c

HEADERS += \
    handshake.h \
    checksum.h
