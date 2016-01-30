#-------------------------------------------------
#
# Project created by QtCreator 2016-01-29T11:32:05
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = da
TEMPLATE = app

LIBS += -lpcap

SOURCES += main.cpp\
        widget.cpp \
    devselectdlg.cpp \
    analyzer.cpp

HEADERS  += widget.h \
    ieee80211_radiotap.h \
    devselectdlg.h \
    analyzer.h \
    ieee80211.h

FORMS    += widget.ui \
    devselectdlg.ui
