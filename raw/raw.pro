TEMPLATE = app
CONFIG += console thread
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.c \
    handshake.c


#unix:!macx: LIBS += -L$$PWD/../../../../../../../usr/lib/x86_64-linux-gnu/ -lpcap
#
#INCLUDEPATH += $$PWD/../../../../../../../usr/lib/x86_64-linux-gnu
#DEPENDPATH += $$PWD/../../../../../../../usr/lib/x86_64-linux-gnu
#
#unix:!macx: PRE_TARGETDEPS += $$PWD/../../../../../../../usr/lib/x86_64-linux-gnu/libpcap.a

HEADERS += \
    handshake.h
