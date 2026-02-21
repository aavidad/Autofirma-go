QT += core gui qml quick network
greaterThan(QT_MAJOR_VERSION, 5): QT += quickcontrols2

CONFIG += c++17

# Evitar dependencia de widgets si no se usa
# QT -= widgets

SOURCES += \
        main.cpp \
        backendbridge.cpp \
        ipcbridge.cpp

HEADERS += \
        backendbridge.h \
        ipcbridge.h

RESOURCES += qml/main.qml

# Configuración de despliegue básica
target.path = /usr/bin
INSTALLS += target
