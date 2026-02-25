/****************************************************************************
** Meta object code from reading C++ file 'ipcbridge.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.13)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "ipcbridge.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ipcbridge.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.13. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_IpcBridge_t {
    QByteArrayData data[75];
    char stringdata0[945];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_IpcBridge_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_IpcBridge_t qt_meta_stringdata_IpcBridge = {
    {
QT_MOC_LITERAL(0, 0, 9), // "IpcBridge"
QT_MOC_LITERAL(1, 10, 18), // "certificatesLoaded"
QT_MOC_LITERAL(2, 29, 0), // ""
QT_MOC_LITERAL(3, 30, 5), // "certs"
QT_MOC_LITERAL(4, 36, 15), // "signingFinished"
QT_MOC_LITERAL(5, 52, 7), // "success"
QT_MOC_LITERAL(6, 60, 7), // "message"
QT_MOC_LITERAL(7, 68, 10), // "outputPath"
QT_MOC_LITERAL(8, 79, 20), // "verificationFinished"
QT_MOC_LITERAL(9, 100, 7), // "details"
QT_MOC_LITERAL(10, 108, 18), // "backendLogReceived"
QT_MOC_LITERAL(11, 127, 3), // "log"
QT_MOC_LITERAL(12, 131, 17), // "expertModeChanged"
QT_MOC_LITERAL(13, 149, 13), // "statusChanged"
QT_MOC_LITERAL(14, 163, 21), // "serviceStatusReceived"
QT_MOC_LITERAL(15, 185, 9), // "installed"
QT_MOC_LITERAL(16, 195, 7), // "running"
QT_MOC_LITERAL(17, 203, 8), // "platform"
QT_MOC_LITERAL(18, 212, 6), // "method"
QT_MOC_LITERAL(19, 219, 21), // "serviceActionFinished"
QT_MOC_LITERAL(20, 241, 2), // "ok"
QT_MOC_LITERAL(21, 244, 14), // "settingsLoaded"
QT_MOC_LITERAL(22, 259, 8), // "settings"
QT_MOC_LITERAL(23, 268, 18), // "pdfPreviewReceived"
QT_MOC_LITERAL(24, 287, 4), // "data"
QT_MOC_LITERAL(25, 292, 5), // "width"
QT_MOC_LITERAL(26, 298, 6), // "height"
QT_MOC_LITERAL(27, 305, 25), // "certificateImportFinished"
QT_MOC_LITERAL(28, 331, 31), // "publicRootsInstallationFinished"
QT_MOC_LITERAL(29, 363, 11), // "onReadyRead"
QT_MOC_LITERAL(30, 375, 11), // "onConnected"
QT_MOC_LITERAL(31, 387, 7), // "onError"
QT_MOC_LITERAL(32, 395, 30), // "QLocalSocket::LocalSocketError"
QT_MOC_LITERAL(33, 426, 5), // "error"
QT_MOC_LITERAL(34, 432, 12), // "startBackend"
QT_MOC_LITERAL(35, 445, 4), // "addr"
QT_MOC_LITERAL(36, 450, 5), // "token"
QT_MOC_LITERAL(37, 456, 4), // "mode"
QT_MOC_LITERAL(38, 461, 12), // "fingerprints"
QT_MOC_LITERAL(39, 474, 6), // "useTLS"
QT_MOC_LITERAL(40, 481, 11), // "stopBackend"
QT_MOC_LITERAL(41, 493, 19), // "canStopOwnedBackend"
QT_MOC_LITERAL(42, 513, 19), // "refreshCertificates"
QT_MOC_LITERAL(43, 533, 8), // "signFile"
QT_MOC_LITERAL(44, 542, 9), // "inputPath"
QT_MOC_LITERAL(45, 552, 9), // "certIndex"
QT_MOC_LITERAL(46, 562, 6), // "format"
QT_MOC_LITERAL(47, 569, 16), // "signFileAdvanced"
QT_MOC_LITERAL(48, 586, 7), // "options"
QT_MOC_LITERAL(49, 594, 10), // "verifyFile"
QT_MOC_LITERAL(50, 605, 12), // "updateStatus"
QT_MOC_LITERAL(51, 618, 3), // "msg"
QT_MOC_LITERAL(52, 622, 12), // "openExternal"
QT_MOC_LITERAL(53, 635, 4), // "path"
QT_MOC_LITERAL(54, 640, 15), // "openCertManager"
QT_MOC_LITERAL(55, 656, 13), // "openLogFolder"
QT_MOC_LITERAL(56, 670, 14), // "openHelpManual"
QT_MOC_LITERAL(57, 685, 17), // "checkCertificates"
QT_MOC_LITERAL(58, 703, 17), // "runTLSDiagnostics"
QT_MOC_LITERAL(59, 721, 22), // "exportDiagnosticReport"
QT_MOC_LITERAL(60, 744, 18), // "clearTLSTrustStore"
QT_MOC_LITERAL(61, 763, 16), // "getServiceStatus"
QT_MOC_LITERAL(62, 780, 14), // "installService"
QT_MOC_LITERAL(63, 795, 16), // "uninstallService"
QT_MOC_LITERAL(64, 812, 12), // "startService"
QT_MOC_LITERAL(65, 825, 11), // "stopService"
QT_MOC_LITERAL(66, 837, 11), // "getSettings"
QT_MOC_LITERAL(67, 849, 12), // "saveSettings"
QT_MOC_LITERAL(68, 862, 13), // "getPdfPreview"
QT_MOC_LITERAL(69, 876, 4), // "page"
QT_MOC_LITERAL(70, 881, 17), // "importCertificate"
QT_MOC_LITERAL(71, 899, 8), // "password"
QT_MOC_LITERAL(72, 908, 18), // "installPublicRoots"
QT_MOC_LITERAL(73, 927, 10), // "expertMode"
QT_MOC_LITERAL(74, 938, 6) // "status"

    },
    "IpcBridge\0certificatesLoaded\0\0certs\0"
    "signingFinished\0success\0message\0"
    "outputPath\0verificationFinished\0details\0"
    "backendLogReceived\0log\0expertModeChanged\0"
    "statusChanged\0serviceStatusReceived\0"
    "installed\0running\0platform\0method\0"
    "serviceActionFinished\0ok\0settingsLoaded\0"
    "settings\0pdfPreviewReceived\0data\0width\0"
    "height\0certificateImportFinished\0"
    "publicRootsInstallationFinished\0"
    "onReadyRead\0onConnected\0onError\0"
    "QLocalSocket::LocalSocketError\0error\0"
    "startBackend\0addr\0token\0mode\0fingerprints\0"
    "useTLS\0stopBackend\0canStopOwnedBackend\0"
    "refreshCertificates\0signFile\0inputPath\0"
    "certIndex\0format\0signFileAdvanced\0"
    "options\0verifyFile\0updateStatus\0msg\0"
    "openExternal\0path\0openCertManager\0"
    "openLogFolder\0openHelpManual\0"
    "checkCertificates\0runTLSDiagnostics\0"
    "exportDiagnosticReport\0clearTLSTrustStore\0"
    "getServiceStatus\0installService\0"
    "uninstallService\0startService\0stopService\0"
    "getSettings\0saveSettings\0getPdfPreview\0"
    "page\0importCertificate\0password\0"
    "installPublicRoots\0expertMode\0status"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_IpcBridge[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      46,   14, // methods
       2,  402, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      12,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,  244,    2, 0x06 /* Public */,
       4,    3,  247,    2, 0x06 /* Public */,
       8,    3,  254,    2, 0x06 /* Public */,
      10,    1,  261,    2, 0x06 /* Public */,
      12,    0,  264,    2, 0x06 /* Public */,
      13,    0,  265,    2, 0x06 /* Public */,
      14,    4,  266,    2, 0x06 /* Public */,
      19,    2,  275,    2, 0x06 /* Public */,
      21,    1,  280,    2, 0x06 /* Public */,
      23,    4,  283,    2, 0x06 /* Public */,
      27,    2,  292,    2, 0x06 /* Public */,
      28,    2,  297,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      29,    0,  302,    2, 0x08 /* Private */,
      30,    0,  303,    2, 0x08 /* Private */,
      31,    1,  304,    2, 0x08 /* Private */,

 // methods: name, argc, parameters, tag, flags
      34,    5,  307,    2, 0x02 /* Public */,
      34,    4,  318,    2, 0x22 /* Public | MethodCloned */,
      34,    3,  327,    2, 0x22 /* Public | MethodCloned */,
      34,    2,  334,    2, 0x22 /* Public | MethodCloned */,
      34,    1,  339,    2, 0x22 /* Public | MethodCloned */,
      40,    0,  342,    2, 0x02 /* Public */,
      41,    0,  343,    2, 0x02 /* Public */,
      42,    0,  344,    2, 0x02 /* Public */,
      43,    4,  345,    2, 0x02 /* Public */,
      47,    4,  354,    2, 0x02 /* Public */,
      49,    1,  363,    2, 0x02 /* Public */,
      50,    1,  366,    2, 0x02 /* Public */,
      52,    1,  369,    2, 0x02 /* Public */,
      54,    0,  372,    2, 0x02 /* Public */,
      55,    0,  373,    2, 0x02 /* Public */,
      56,    0,  374,    2, 0x02 /* Public */,
      57,    0,  375,    2, 0x02 /* Public */,
      58,    0,  376,    2, 0x02 /* Public */,
      59,    0,  377,    2, 0x02 /* Public */,
      60,    0,  378,    2, 0x02 /* Public */,
      61,    0,  379,    2, 0x02 /* Public */,
      62,    0,  380,    2, 0x02 /* Public */,
      63,    0,  381,    2, 0x02 /* Public */,
      64,    0,  382,    2, 0x02 /* Public */,
      65,    0,  383,    2, 0x02 /* Public */,
      66,    0,  384,    2, 0x02 /* Public */,
      67,    1,  385,    2, 0x02 /* Public */,
      68,    2,  388,    2, 0x02 /* Public */,
      68,    1,  393,    2, 0x22 /* Public | MethodCloned */,
      70,    2,  396,    2, 0x02 /* Public */,
      72,    0,  401,    2, 0x02 /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::QVariantList,    3,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString, QMetaType::QString,    5,    6,    7,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString, QMetaType::QVariantMap,    5,    6,    9,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool, QMetaType::Bool, QMetaType::QString, QMetaType::QString,   15,   16,   17,   18,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   20,    6,
    QMetaType::Void, QMetaType::QVariantMap,   22,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString, QMetaType::Double, QMetaType::Double,   20,   24,   25,   26,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   20,    6,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   20,    6,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 32,   33,

 // methods: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::Bool,   35,   36,   37,   38,   39,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString,   35,   36,   37,   38,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString,   35,   36,   37,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   35,   36,
    QMetaType::Void, QMetaType::QString,   35,
    QMetaType::Void,
    QMetaType::Bool,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QString,   44,    7,   45,   46,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QVariantMap,   44,    7,   45,   48,
    QMetaType::Void, QMetaType::QString,   44,
    QMetaType::Void, QMetaType::QString,   51,
    QMetaType::Void, QMetaType::QString,   53,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QVariantMap,   22,
    QMetaType::Void, QMetaType::QString, QMetaType::Int,   53,   69,
    QMetaType::Void, QMetaType::QString,   53,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   53,   71,
    QMetaType::Void,

 // properties: name, type, flags
      73, QMetaType::Bool, 0x00495103,
      74, QMetaType::QString, 0x00495001,

 // properties: notify_signal_id
       4,
       5,

       0        // eod
};

void IpcBridge::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<IpcBridge *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->certificatesLoaded((*reinterpret_cast< QVariantList(*)>(_a[1]))); break;
        case 1: _t->signingFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3]))); break;
        case 2: _t->verificationFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< QVariantMap(*)>(_a[3]))); break;
        case 3: _t->backendLogReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 4: _t->expertModeChanged(); break;
        case 5: _t->statusChanged(); break;
        case 6: _t->serviceStatusReceived((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3])),(*reinterpret_cast< QString(*)>(_a[4]))); break;
        case 7: _t->serviceActionFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 8: _t->settingsLoaded((*reinterpret_cast< QVariantMap(*)>(_a[1]))); break;
        case 9: _t->pdfPreviewReceived((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< double(*)>(_a[3])),(*reinterpret_cast< double(*)>(_a[4]))); break;
        case 10: _t->certificateImportFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 11: _t->publicRootsInstallationFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 12: _t->onReadyRead(); break;
        case 13: _t->onConnected(); break;
        case 14: _t->onError((*reinterpret_cast< QLocalSocket::LocalSocketError(*)>(_a[1]))); break;
        case 15: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3])),(*reinterpret_cast< const QString(*)>(_a[4])),(*reinterpret_cast< bool(*)>(_a[5]))); break;
        case 16: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3])),(*reinterpret_cast< const QString(*)>(_a[4]))); break;
        case 17: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3]))); break;
        case 18: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 19: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 20: _t->stopBackend(); break;
        case 21: { bool _r = _t->canStopOwnedBackend();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 22: _t->refreshCertificates(); break;
        case 23: _t->signFile((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3])),(*reinterpret_cast< const QString(*)>(_a[4]))); break;
        case 24: _t->signFileAdvanced((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3])),(*reinterpret_cast< const QVariantMap(*)>(_a[4]))); break;
        case 25: _t->verifyFile((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 26: _t->updateStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 27: _t->openExternal((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 28: _t->openCertManager(); break;
        case 29: _t->openLogFolder(); break;
        case 30: _t->openHelpManual(); break;
        case 31: _t->checkCertificates(); break;
        case 32: _t->runTLSDiagnostics(); break;
        case 33: _t->exportDiagnosticReport(); break;
        case 34: _t->clearTLSTrustStore(); break;
        case 35: _t->getServiceStatus(); break;
        case 36: _t->installService(); break;
        case 37: _t->uninstallService(); break;
        case 38: _t->startService(); break;
        case 39: _t->stopService(); break;
        case 40: _t->getSettings(); break;
        case 41: _t->saveSettings((*reinterpret_cast< const QVariantMap(*)>(_a[1]))); break;
        case 42: _t->getPdfPreview((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 43: _t->getPdfPreview((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 44: _t->importCertificate((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 45: _t->installPublicRoots(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (IpcBridge::*)(QVariantList );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::certificatesLoaded)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::signingFinished)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString , QVariantMap );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::verificationFinished)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::backendLogReceived)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::expertModeChanged)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::statusChanged)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , bool , QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::serviceStatusReceived)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::serviceActionFinished)) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(QVariantMap );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::settingsLoaded)) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString , double , double );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::pdfPreviewReceived)) {
                *result = 9;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::certificateImportFinished)) {
                *result = 10;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IpcBridge::publicRootsInstallationFinished)) {
                *result = 11;
                return;
            }
        }
    }
#ifndef QT_NO_PROPERTIES
    else if (_c == QMetaObject::ReadProperty) {
        auto *_t = static_cast<IpcBridge *>(_o);
        (void)_t;
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast< bool*>(_v) = _t->expertMode(); break;
        case 1: *reinterpret_cast< QString*>(_v) = _t->status(); break;
        default: break;
        }
    } else if (_c == QMetaObject::WriteProperty) {
        auto *_t = static_cast<IpcBridge *>(_o);
        (void)_t;
        void *_v = _a[0];
        switch (_id) {
        case 0: _t->setExpertMode(*reinterpret_cast< bool*>(_v)); break;
        default: break;
        }
    } else if (_c == QMetaObject::ResetProperty) {
    }
#endif // QT_NO_PROPERTIES
}

QT_INIT_METAOBJECT const QMetaObject IpcBridge::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_IpcBridge.data,
    qt_meta_data_IpcBridge,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *IpcBridge::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *IpcBridge::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_IpcBridge.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int IpcBridge::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 46)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 46;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 46)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 46;
    }
#ifndef QT_NO_PROPERTIES
    else if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyDesignable) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyScriptable) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyStored) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyEditable) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyUser) {
        _id -= 2;
    }
#endif // QT_NO_PROPERTIES
    return _id;
}

// SIGNAL 0
void IpcBridge::certificatesLoaded(QVariantList _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void IpcBridge::signingFinished(bool _t1, QString _t2, QString _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void IpcBridge::verificationFinished(bool _t1, QString _t2, QVariantMap _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void IpcBridge::backendLogReceived(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void IpcBridge::expertModeChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 4, nullptr);
}

// SIGNAL 5
void IpcBridge::statusChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 5, nullptr);
}

// SIGNAL 6
void IpcBridge::serviceStatusReceived(bool _t1, bool _t2, QString _t3, QString _t4)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t4))) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}

// SIGNAL 7
void IpcBridge::serviceActionFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 7, _a);
}

// SIGNAL 8
void IpcBridge::settingsLoaded(QVariantMap _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}

// SIGNAL 9
void IpcBridge::pdfPreviewReceived(bool _t1, QString _t2, double _t3, double _t4)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t4))) };
    QMetaObject::activate(this, &staticMetaObject, 9, _a);
}

// SIGNAL 10
void IpcBridge::certificateImportFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 10, _a);
}

// SIGNAL 11
void IpcBridge::publicRootsInstallationFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 11, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
