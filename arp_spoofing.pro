TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap
LIBS += -lpthread

SOURCES += main.c
