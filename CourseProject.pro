#-------------------------------------------------
#
# Project created by QtCreator 2023-04-19T19:40:32
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CourseProject
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    multhread.cpp \
    datapacket.cpp

HEADERS  += mainwindow.h \
    multhread.h \
    packetHeader.h \
    datapacket.h

FORMS    += mainwindow.ui

INCLUDEPATH += "D:/Qt/WpdPack/Include"

LIBS += "-LD:/Qt/WpdPack/Lib" -lwpcap -lPacket -lws2_32

RESOURCES += \
    src/src.qrc

CONFIG += C++11
