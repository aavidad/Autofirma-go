/****************************************************************************
** Meta object code from reading C++ file 'backendbridge.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.13)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "backendbridge.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'backendbridge.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.13. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_BackendBridge_t {
    QByteArrayData data[76];
    char stringdata0[980];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_BackendBridge_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_BackendBridge_t qt_meta_stringdata_BackendBridge = {
    {
QT_MOC_LITERAL(0, 0, 13), // "BackendBridge"
QT_MOC_LITERAL(1, 14, 13), // "statusChanged"
QT_MOC_LITERAL(2, 28, 0), // ""
QT_MOC_LITERAL(3, 29, 17), // "expertModeChanged"
QT_MOC_LITERAL(4, 47, 18), // "certificatesLoaded"
QT_MOC_LITERAL(5, 66, 5), // "certs"
QT_MOC_LITERAL(6, 72, 15), // "signingFinished"
QT_MOC_LITERAL(7, 88, 7), // "success"
QT_MOC_LITERAL(8, 96, 7), // "message"
QT_MOC_LITERAL(9, 104, 10), // "outputPath"
QT_MOC_LITERAL(10, 115, 20), // "verificationFinished"
QT_MOC_LITERAL(11, 136, 7), // "details"
QT_MOC_LITERAL(12, 144, 18), // "backendLogReceived"
QT_MOC_LITERAL(13, 163, 3), // "log"
QT_MOC_LITERAL(14, 167, 21), // "serviceStatusReceived"
QT_MOC_LITERAL(15, 189, 9), // "installed"
QT_MOC_LITERAL(16, 199, 7), // "running"
QT_MOC_LITERAL(17, 207, 8), // "platform"
QT_MOC_LITERAL(18, 216, 6), // "method"
QT_MOC_LITERAL(19, 223, 21), // "serviceActionFinished"
QT_MOC_LITERAL(20, 245, 2), // "ok"
QT_MOC_LITERAL(21, 248, 14), // "settingsLoaded"
QT_MOC_LITERAL(22, 263, 8), // "settings"
QT_MOC_LITERAL(23, 272, 18), // "pdfPreviewReceived"
QT_MOC_LITERAL(24, 291, 4), // "data"
QT_MOC_LITERAL(25, 296, 5), // "width"
QT_MOC_LITERAL(26, 302, 6), // "height"
QT_MOC_LITERAL(27, 309, 25), // "certificateImportFinished"
QT_MOC_LITERAL(28, 335, 31), // "publicRootsInstallationFinished"
QT_MOC_LITERAL(29, 367, 18), // "onBackendReadyRead"
QT_MOC_LITERAL(30, 386, 22), // "onNetworkReplyFinished"
QT_MOC_LITERAL(31, 409, 14), // "QNetworkReply*"
QT_MOC_LITERAL(32, 424, 5), // "reply"
QT_MOC_LITERAL(33, 430, 12), // "startBackend"
QT_MOC_LITERAL(34, 443, 4), // "addr"
QT_MOC_LITERAL(35, 448, 5), // "token"
QT_MOC_LITERAL(36, 454, 4), // "mode"
QT_MOC_LITERAL(37, 459, 12), // "fingerprints"
QT_MOC_LITERAL(38, 472, 6), // "useTLS"
QT_MOC_LITERAL(39, 479, 11), // "stopBackend"
QT_MOC_LITERAL(40, 491, 19), // "canStopOwnedBackend"
QT_MOC_LITERAL(41, 511, 8), // "signFile"
QT_MOC_LITERAL(42, 520, 9), // "inputPath"
QT_MOC_LITERAL(43, 530, 9), // "certIndex"
QT_MOC_LITERAL(44, 540, 6), // "format"
QT_MOC_LITERAL(45, 547, 16), // "signFileAdvanced"
QT_MOC_LITERAL(46, 564, 7), // "options"
QT_MOC_LITERAL(47, 572, 19), // "refreshCertificates"
QT_MOC_LITERAL(48, 592, 10), // "verifyFile"
QT_MOC_LITERAL(49, 603, 12), // "updateStatus"
QT_MOC_LITERAL(50, 616, 3), // "msg"
QT_MOC_LITERAL(51, 620, 12), // "openExternal"
QT_MOC_LITERAL(52, 633, 4), // "path"
QT_MOC_LITERAL(53, 638, 15), // "openCertManager"
QT_MOC_LITERAL(54, 654, 13), // "openLogFolder"
QT_MOC_LITERAL(55, 668, 14), // "openHelpManual"
QT_MOC_LITERAL(56, 683, 17), // "checkCertificates"
QT_MOC_LITERAL(57, 701, 17), // "runTLSDiagnostics"
QT_MOC_LITERAL(58, 719, 22), // "exportDiagnosticReport"
QT_MOC_LITERAL(59, 742, 18), // "clearTLSTrustStore"
QT_MOC_LITERAL(60, 761, 16), // "getServiceStatus"
QT_MOC_LITERAL(61, 778, 14), // "installService"
QT_MOC_LITERAL(62, 793, 16), // "uninstallService"
QT_MOC_LITERAL(63, 810, 12), // "startService"
QT_MOC_LITERAL(64, 823, 11), // "stopService"
QT_MOC_LITERAL(65, 835, 11), // "getSettings"
QT_MOC_LITERAL(66, 847, 12), // "saveSettings"
QT_MOC_LITERAL(67, 860, 13), // "getPdfPreview"
QT_MOC_LITERAL(68, 874, 4), // "page"
QT_MOC_LITERAL(69, 879, 22), // "installCamerfirmaCerts"
QT_MOC_LITERAL(70, 902, 17), // "importCertificate"
QT_MOC_LITERAL(71, 920, 8), // "password"
QT_MOC_LITERAL(72, 929, 18), // "installPublicRoots"
QT_MOC_LITERAL(73, 948, 13), // "getAppDirPath"
QT_MOC_LITERAL(74, 962, 6), // "status"
QT_MOC_LITERAL(75, 969, 10) // "expertMode"

    },
    "BackendBridge\0statusChanged\0\0"
    "expertModeChanged\0certificatesLoaded\0"
    "certs\0signingFinished\0success\0message\0"
    "outputPath\0verificationFinished\0details\0"
    "backendLogReceived\0log\0serviceStatusReceived\0"
    "installed\0running\0platform\0method\0"
    "serviceActionFinished\0ok\0settingsLoaded\0"
    "settings\0pdfPreviewReceived\0data\0width\0"
    "height\0certificateImportFinished\0"
    "publicRootsInstallationFinished\0"
    "onBackendReadyRead\0onNetworkReplyFinished\0"
    "QNetworkReply*\0reply\0startBackend\0"
    "addr\0token\0mode\0fingerprints\0useTLS\0"
    "stopBackend\0canStopOwnedBackend\0"
    "signFile\0inputPath\0certIndex\0format\0"
    "signFileAdvanced\0options\0refreshCertificates\0"
    "verifyFile\0updateStatus\0msg\0openExternal\0"
    "path\0openCertManager\0openLogFolder\0"
    "openHelpManual\0checkCertificates\0"
    "runTLSDiagnostics\0exportDiagnosticReport\0"
    "clearTLSTrustStore\0getServiceStatus\0"
    "installService\0uninstallService\0"
    "startService\0stopService\0getSettings\0"
    "saveSettings\0getPdfPreview\0page\0"
    "installCamerfirmaCerts\0importCertificate\0"
    "password\0installPublicRoots\0getAppDirPath\0"
    "status\0expertMode"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_BackendBridge[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      46,   14, // methods
       2,  400, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      12,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,  244,    2, 0x06 /* Public */,
       3,    0,  245,    2, 0x06 /* Public */,
       4,    1,  246,    2, 0x06 /* Public */,
       6,    3,  249,    2, 0x06 /* Public */,
      10,    3,  256,    2, 0x06 /* Public */,
      12,    1,  263,    2, 0x06 /* Public */,
      14,    4,  266,    2, 0x06 /* Public */,
      19,    2,  275,    2, 0x06 /* Public */,
      21,    1,  280,    2, 0x06 /* Public */,
      23,    4,  283,    2, 0x06 /* Public */,
      27,    2,  292,    2, 0x06 /* Public */,
      28,    2,  297,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      29,    0,  302,    2, 0x08 /* Private */,
      30,    1,  303,    2, 0x08 /* Private */,

 // methods: name, argc, parameters, tag, flags
      33,    5,  306,    2, 0x02 /* Public */,
      33,    4,  317,    2, 0x22 /* Public | MethodCloned */,
      33,    3,  326,    2, 0x22 /* Public | MethodCloned */,
      33,    2,  333,    2, 0x22 /* Public | MethodCloned */,
      39,    0,  338,    2, 0x02 /* Public */,
      40,    0,  339,    2, 0x02 /* Public */,
      41,    4,  340,    2, 0x02 /* Public */,
      45,    4,  349,    2, 0x02 /* Public */,
      47,    0,  358,    2, 0x02 /* Public */,
      48,    1,  359,    2, 0x02 /* Public */,
      49,    1,  362,    2, 0x02 /* Public */,
      51,    1,  365,    2, 0x02 /* Public */,
      53,    0,  368,    2, 0x02 /* Public */,
      54,    0,  369,    2, 0x02 /* Public */,
      55,    0,  370,    2, 0x02 /* Public */,
      56,    0,  371,    2, 0x02 /* Public */,
      57,    0,  372,    2, 0x02 /* Public */,
      58,    0,  373,    2, 0x02 /* Public */,
      59,    0,  374,    2, 0x02 /* Public */,
      60,    0,  375,    2, 0x02 /* Public */,
      61,    0,  376,    2, 0x02 /* Public */,
      62,    0,  377,    2, 0x02 /* Public */,
      63,    0,  378,    2, 0x02 /* Public */,
      64,    0,  379,    2, 0x02 /* Public */,
      65,    0,  380,    2, 0x02 /* Public */,
      66,    1,  381,    2, 0x02 /* Public */,
      67,    2,  384,    2, 0x02 /* Public */,
      67,    1,  389,    2, 0x22 /* Public | MethodCloned */,
      69,    0,  392,    2, 0x02 /* Public */,
      70,    2,  393,    2, 0x02 /* Public */,
      72,    0,  398,    2, 0x02 /* Public */,
      73,    0,  399,    2, 0x02 /* Public */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QVariantList,    5,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString, QMetaType::QString,    7,    8,    9,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString, QMetaType::QVariantMap,    7,    8,   11,
    QMetaType::Void, QMetaType::QString,   13,
    QMetaType::Void, QMetaType::Bool, QMetaType::Bool, QMetaType::QString, QMetaType::QString,   15,   16,   17,   18,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   20,    8,
    QMetaType::Void, QMetaType::QVariantMap,   22,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString, QMetaType::Double, QMetaType::Double,   20,   24,   25,   26,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   20,    8,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   20,    8,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 31,   32,

 // methods: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::Bool,   34,   35,   36,   37,   38,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString,   34,   35,   36,   37,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString,   34,   35,   36,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   34,   35,
    QMetaType::Void,
    QMetaType::Bool,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QString,   42,    9,   43,   44,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QVariantMap,   42,    9,   43,   46,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   42,
    QMetaType::Void, QMetaType::QString,   50,
    QMetaType::Void, QMetaType::QString,   52,
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
    QMetaType::Void, QMetaType::QString, QMetaType::Int,   52,   68,
    QMetaType::Void, QMetaType::QString,   52,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   52,   71,
    QMetaType::Void,
    QMetaType::QString,

 // properties: name, type, flags
      74, QMetaType::QString, 0x00495001,
      75, QMetaType::Bool, 0x00495103,

 // properties: notify_signal_id
       0,
       1,

       0        // eod
};

void BackendBridge::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<BackendBridge *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->statusChanged(); break;
        case 1: _t->expertModeChanged(); break;
        case 2: _t->certificatesLoaded((*reinterpret_cast< QVariantList(*)>(_a[1]))); break;
        case 3: _t->signingFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3]))); break;
        case 4: _t->verificationFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< QVariantMap(*)>(_a[3]))); break;
        case 5: _t->backendLogReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 6: _t->serviceStatusReceived((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3])),(*reinterpret_cast< QString(*)>(_a[4]))); break;
        case 7: _t->serviceActionFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 8: _t->settingsLoaded((*reinterpret_cast< QVariantMap(*)>(_a[1]))); break;
        case 9: _t->pdfPreviewReceived((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< double(*)>(_a[3])),(*reinterpret_cast< double(*)>(_a[4]))); break;
        case 10: _t->certificateImportFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 11: _t->publicRootsInstallationFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 12: _t->onBackendReadyRead(); break;
        case 13: _t->onNetworkReplyFinished((*reinterpret_cast< QNetworkReply*(*)>(_a[1]))); break;
        case 14: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3])),(*reinterpret_cast< const QString(*)>(_a[4])),(*reinterpret_cast< bool(*)>(_a[5]))); break;
        case 15: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3])),(*reinterpret_cast< const QString(*)>(_a[4]))); break;
        case 16: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3]))); break;
        case 17: _t->startBackend((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 18: _t->stopBackend(); break;
        case 19: { bool _r = _t->canStopOwnedBackend();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 20: _t->signFile((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3])),(*reinterpret_cast< const QString(*)>(_a[4]))); break;
        case 21: _t->signFileAdvanced((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3])),(*reinterpret_cast< const QVariantMap(*)>(_a[4]))); break;
        case 22: _t->refreshCertificates(); break;
        case 23: _t->verifyFile((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 24: _t->updateStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 25: _t->openExternal((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 26: _t->openCertManager(); break;
        case 27: _t->openLogFolder(); break;
        case 28: _t->openHelpManual(); break;
        case 29: _t->checkCertificates(); break;
        case 30: _t->runTLSDiagnostics(); break;
        case 31: _t->exportDiagnosticReport(); break;
        case 32: _t->clearTLSTrustStore(); break;
        case 33: _t->getServiceStatus(); break;
        case 34: _t->installService(); break;
        case 35: _t->uninstallService(); break;
        case 36: _t->startService(); break;
        case 37: _t->stopService(); break;
        case 38: _t->getSettings(); break;
        case 39: _t->saveSettings((*reinterpret_cast< const QVariantMap(*)>(_a[1]))); break;
        case 40: _t->getPdfPreview((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 41: _t->getPdfPreview((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 42: _t->installCamerfirmaCerts(); break;
        case 43: _t->importCertificate((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 44: _t->installPublicRoots(); break;
        case 45: { QString _r = _t->getAppDirPath();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 13:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QNetworkReply* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (BackendBridge::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::statusChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::expertModeChanged)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(QVariantList );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::certificatesLoaded)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::signingFinished)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString , QVariantMap );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::verificationFinished)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::backendLogReceived)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , bool , QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::serviceStatusReceived)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::serviceActionFinished)) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(QVariantMap );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::settingsLoaded)) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString , double , double );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::pdfPreviewReceived)) {
                *result = 9;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::certificateImportFinished)) {
                *result = 10;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BackendBridge::publicRootsInstallationFinished)) {
                *result = 11;
                return;
            }
        }
    }
#ifndef QT_NO_PROPERTIES
    else if (_c == QMetaObject::ReadProperty) {
        auto *_t = static_cast<BackendBridge *>(_o);
        (void)_t;
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast< QString*>(_v) = _t->status(); break;
        case 1: *reinterpret_cast< bool*>(_v) = _t->expertMode(); break;
        default: break;
        }
    } else if (_c == QMetaObject::WriteProperty) {
        auto *_t = static_cast<BackendBridge *>(_o);
        (void)_t;
        void *_v = _a[0];
        switch (_id) {
        case 1: _t->setExpertMode(*reinterpret_cast< bool*>(_v)); break;
        default: break;
        }
    } else if (_c == QMetaObject::ResetProperty) {
    }
#endif // QT_NO_PROPERTIES
}

QT_INIT_METAOBJECT const QMetaObject BackendBridge::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_BackendBridge.data,
    qt_meta_data_BackendBridge,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *BackendBridge::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *BackendBridge::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_BackendBridge.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int BackendBridge::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
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
            qt_static_metacall(this, _c, _id, _a);
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
void BackendBridge::statusChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void BackendBridge::expertModeChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void BackendBridge::certificatesLoaded(QVariantList _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void BackendBridge::signingFinished(bool _t1, QString _t2, QString _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void BackendBridge::verificationFinished(bool _t1, QString _t2, QVariantMap _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void BackendBridge::backendLogReceived(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void BackendBridge::serviceStatusReceived(bool _t1, bool _t2, QString _t3, QString _t4)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t4))) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}

// SIGNAL 7
void BackendBridge::serviceActionFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 7, _a);
}

// SIGNAL 8
void BackendBridge::settingsLoaded(QVariantMap _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}

// SIGNAL 9
void BackendBridge::pdfPreviewReceived(bool _t1, QString _t2, double _t3, double _t4)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t4))) };
    QMetaObject::activate(this, &staticMetaObject, 9, _a);
}

// SIGNAL 10
void BackendBridge::certificateImportFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 10, _a);
}

// SIGNAL 11
void BackendBridge::publicRootsInstallationFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 11, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
