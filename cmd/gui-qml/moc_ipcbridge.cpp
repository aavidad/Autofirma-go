/****************************************************************************
** Meta object code from reading C++ file 'ipcbridge.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "ipcbridge.h"
#include <QtNetwork/QSslError>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ipcbridge.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.4.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
namespace {
struct qt_meta_stringdata_IpcBridge_t {
    uint offsetsAndSizes[150];
    char stringdata0[10];
    char stringdata1[19];
    char stringdata2[1];
    char stringdata3[6];
    char stringdata4[16];
    char stringdata5[8];
    char stringdata6[8];
    char stringdata7[11];
    char stringdata8[21];
    char stringdata9[8];
    char stringdata10[19];
    char stringdata11[4];
    char stringdata12[18];
    char stringdata13[14];
    char stringdata14[22];
    char stringdata15[10];
    char stringdata16[8];
    char stringdata17[9];
    char stringdata18[7];
    char stringdata19[22];
    char stringdata20[3];
    char stringdata21[15];
    char stringdata22[9];
    char stringdata23[19];
    char stringdata24[5];
    char stringdata25[6];
    char stringdata26[7];
    char stringdata27[26];
    char stringdata28[32];
    char stringdata29[12];
    char stringdata30[12];
    char stringdata31[8];
    char stringdata32[31];
    char stringdata33[6];
    char stringdata34[13];
    char stringdata35[5];
    char stringdata36[6];
    char stringdata37[5];
    char stringdata38[13];
    char stringdata39[7];
    char stringdata40[12];
    char stringdata41[20];
    char stringdata42[20];
    char stringdata43[9];
    char stringdata44[10];
    char stringdata45[10];
    char stringdata46[7];
    char stringdata47[17];
    char stringdata48[8];
    char stringdata49[11];
    char stringdata50[13];
    char stringdata51[4];
    char stringdata52[13];
    char stringdata53[5];
    char stringdata54[16];
    char stringdata55[14];
    char stringdata56[15];
    char stringdata57[18];
    char stringdata58[18];
    char stringdata59[23];
    char stringdata60[19];
    char stringdata61[17];
    char stringdata62[15];
    char stringdata63[17];
    char stringdata64[13];
    char stringdata65[12];
    char stringdata66[12];
    char stringdata67[13];
    char stringdata68[14];
    char stringdata69[5];
    char stringdata70[18];
    char stringdata71[9];
    char stringdata72[19];
    char stringdata73[11];
    char stringdata74[7];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_IpcBridge_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_IpcBridge_t qt_meta_stringdata_IpcBridge = {
    {
        QT_MOC_LITERAL(0, 9),  // "IpcBridge"
        QT_MOC_LITERAL(10, 18),  // "certificatesLoaded"
        QT_MOC_LITERAL(29, 0),  // ""
        QT_MOC_LITERAL(30, 5),  // "certs"
        QT_MOC_LITERAL(36, 15),  // "signingFinished"
        QT_MOC_LITERAL(52, 7),  // "success"
        QT_MOC_LITERAL(60, 7),  // "message"
        QT_MOC_LITERAL(68, 10),  // "outputPath"
        QT_MOC_LITERAL(79, 20),  // "verificationFinished"
        QT_MOC_LITERAL(100, 7),  // "details"
        QT_MOC_LITERAL(108, 18),  // "backendLogReceived"
        QT_MOC_LITERAL(127, 3),  // "log"
        QT_MOC_LITERAL(131, 17),  // "expertModeChanged"
        QT_MOC_LITERAL(149, 13),  // "statusChanged"
        QT_MOC_LITERAL(163, 21),  // "serviceStatusReceived"
        QT_MOC_LITERAL(185, 9),  // "installed"
        QT_MOC_LITERAL(195, 7),  // "running"
        QT_MOC_LITERAL(203, 8),  // "platform"
        QT_MOC_LITERAL(212, 6),  // "method"
        QT_MOC_LITERAL(219, 21),  // "serviceActionFinished"
        QT_MOC_LITERAL(241, 2),  // "ok"
        QT_MOC_LITERAL(244, 14),  // "settingsLoaded"
        QT_MOC_LITERAL(259, 8),  // "settings"
        QT_MOC_LITERAL(268, 18),  // "pdfPreviewReceived"
        QT_MOC_LITERAL(287, 4),  // "data"
        QT_MOC_LITERAL(292, 5),  // "width"
        QT_MOC_LITERAL(298, 6),  // "height"
        QT_MOC_LITERAL(305, 25),  // "certificateImportFinished"
        QT_MOC_LITERAL(331, 31),  // "publicRootsInstallationFinished"
        QT_MOC_LITERAL(363, 11),  // "onReadyRead"
        QT_MOC_LITERAL(375, 11),  // "onConnected"
        QT_MOC_LITERAL(387, 7),  // "onError"
        QT_MOC_LITERAL(395, 30),  // "QLocalSocket::LocalSocketError"
        QT_MOC_LITERAL(426, 5),  // "error"
        QT_MOC_LITERAL(432, 12),  // "startBackend"
        QT_MOC_LITERAL(445, 4),  // "addr"
        QT_MOC_LITERAL(450, 5),  // "token"
        QT_MOC_LITERAL(456, 4),  // "mode"
        QT_MOC_LITERAL(461, 12),  // "fingerprints"
        QT_MOC_LITERAL(474, 6),  // "useTLS"
        QT_MOC_LITERAL(481, 11),  // "stopBackend"
        QT_MOC_LITERAL(493, 19),  // "canStopOwnedBackend"
        QT_MOC_LITERAL(513, 19),  // "refreshCertificates"
        QT_MOC_LITERAL(533, 8),  // "signFile"
        QT_MOC_LITERAL(542, 9),  // "inputPath"
        QT_MOC_LITERAL(552, 9),  // "certIndex"
        QT_MOC_LITERAL(562, 6),  // "format"
        QT_MOC_LITERAL(569, 16),  // "signFileAdvanced"
        QT_MOC_LITERAL(586, 7),  // "options"
        QT_MOC_LITERAL(594, 10),  // "verifyFile"
        QT_MOC_LITERAL(605, 12),  // "updateStatus"
        QT_MOC_LITERAL(618, 3),  // "msg"
        QT_MOC_LITERAL(622, 12),  // "openExternal"
        QT_MOC_LITERAL(635, 4),  // "path"
        QT_MOC_LITERAL(640, 15),  // "openCertManager"
        QT_MOC_LITERAL(656, 13),  // "openLogFolder"
        QT_MOC_LITERAL(670, 14),  // "openHelpManual"
        QT_MOC_LITERAL(685, 17),  // "checkCertificates"
        QT_MOC_LITERAL(703, 17),  // "runTLSDiagnostics"
        QT_MOC_LITERAL(721, 22),  // "exportDiagnosticReport"
        QT_MOC_LITERAL(744, 18),  // "clearTLSTrustStore"
        QT_MOC_LITERAL(763, 16),  // "getServiceStatus"
        QT_MOC_LITERAL(780, 14),  // "installService"
        QT_MOC_LITERAL(795, 16),  // "uninstallService"
        QT_MOC_LITERAL(812, 12),  // "startService"
        QT_MOC_LITERAL(825, 11),  // "stopService"
        QT_MOC_LITERAL(837, 11),  // "getSettings"
        QT_MOC_LITERAL(849, 12),  // "saveSettings"
        QT_MOC_LITERAL(862, 13),  // "getPdfPreview"
        QT_MOC_LITERAL(876, 4),  // "page"
        QT_MOC_LITERAL(881, 17),  // "importCertificate"
        QT_MOC_LITERAL(899, 8),  // "password"
        QT_MOC_LITERAL(908, 18),  // "installPublicRoots"
        QT_MOC_LITERAL(927, 10),  // "expertMode"
        QT_MOC_LITERAL(938, 6)   // "status"
    },
    "IpcBridge",
    "certificatesLoaded",
    "",
    "certs",
    "signingFinished",
    "success",
    "message",
    "outputPath",
    "verificationFinished",
    "details",
    "backendLogReceived",
    "log",
    "expertModeChanged",
    "statusChanged",
    "serviceStatusReceived",
    "installed",
    "running",
    "platform",
    "method",
    "serviceActionFinished",
    "ok",
    "settingsLoaded",
    "settings",
    "pdfPreviewReceived",
    "data",
    "width",
    "height",
    "certificateImportFinished",
    "publicRootsInstallationFinished",
    "onReadyRead",
    "onConnected",
    "onError",
    "QLocalSocket::LocalSocketError",
    "error",
    "startBackend",
    "addr",
    "token",
    "mode",
    "fingerprints",
    "useTLS",
    "stopBackend",
    "canStopOwnedBackend",
    "refreshCertificates",
    "signFile",
    "inputPath",
    "certIndex",
    "format",
    "signFileAdvanced",
    "options",
    "verifyFile",
    "updateStatus",
    "msg",
    "openExternal",
    "path",
    "openCertManager",
    "openLogFolder",
    "openHelpManual",
    "checkCertificates",
    "runTLSDiagnostics",
    "exportDiagnosticReport",
    "clearTLSTrustStore",
    "getServiceStatus",
    "installService",
    "uninstallService",
    "startService",
    "stopService",
    "getSettings",
    "saveSettings",
    "getPdfPreview",
    "page",
    "importCertificate",
    "password",
    "installPublicRoots",
    "expertMode",
    "status"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_IpcBridge[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
      46,   14, // methods
       2,  448, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      12,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,  290,    2, 0x06,    3 /* Public */,
       4,    3,  293,    2, 0x06,    5 /* Public */,
       8,    3,  300,    2, 0x06,    9 /* Public */,
      10,    1,  307,    2, 0x06,   13 /* Public */,
      12,    0,  310,    2, 0x06,   15 /* Public */,
      13,    0,  311,    2, 0x06,   16 /* Public */,
      14,    4,  312,    2, 0x06,   17 /* Public */,
      19,    2,  321,    2, 0x06,   22 /* Public */,
      21,    1,  326,    2, 0x06,   25 /* Public */,
      23,    4,  329,    2, 0x06,   27 /* Public */,
      27,    2,  338,    2, 0x06,   32 /* Public */,
      28,    2,  343,    2, 0x06,   35 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      29,    0,  348,    2, 0x08,   38 /* Private */,
      30,    0,  349,    2, 0x08,   39 /* Private */,
      31,    1,  350,    2, 0x08,   40 /* Private */,

 // methods: name, argc, parameters, tag, flags, initial metatype offsets
      34,    5,  353,    2, 0x02,   42 /* Public */,
      34,    4,  364,    2, 0x22,   48 /* Public | MethodCloned */,
      34,    3,  373,    2, 0x22,   53 /* Public | MethodCloned */,
      34,    2,  380,    2, 0x22,   57 /* Public | MethodCloned */,
      34,    1,  385,    2, 0x22,   60 /* Public | MethodCloned */,
      40,    0,  388,    2, 0x02,   62 /* Public */,
      41,    0,  389,    2, 0x102,   63 /* Public | MethodIsConst  */,
      42,    0,  390,    2, 0x02,   64 /* Public */,
      43,    4,  391,    2, 0x02,   65 /* Public */,
      47,    4,  400,    2, 0x02,   70 /* Public */,
      49,    1,  409,    2, 0x02,   75 /* Public */,
      50,    1,  412,    2, 0x02,   77 /* Public */,
      52,    1,  415,    2, 0x02,   79 /* Public */,
      54,    0,  418,    2, 0x02,   81 /* Public */,
      55,    0,  419,    2, 0x02,   82 /* Public */,
      56,    0,  420,    2, 0x02,   83 /* Public */,
      57,    0,  421,    2, 0x02,   84 /* Public */,
      58,    0,  422,    2, 0x02,   85 /* Public */,
      59,    0,  423,    2, 0x02,   86 /* Public */,
      60,    0,  424,    2, 0x02,   87 /* Public */,
      61,    0,  425,    2, 0x02,   88 /* Public */,
      62,    0,  426,    2, 0x02,   89 /* Public */,
      63,    0,  427,    2, 0x02,   90 /* Public */,
      64,    0,  428,    2, 0x02,   91 /* Public */,
      65,    0,  429,    2, 0x02,   92 /* Public */,
      66,    0,  430,    2, 0x02,   93 /* Public */,
      67,    1,  431,    2, 0x02,   94 /* Public */,
      68,    2,  434,    2, 0x02,   96 /* Public */,
      68,    1,  439,    2, 0x22,   99 /* Public | MethodCloned */,
      70,    2,  442,    2, 0x02,  101 /* Public */,
      72,    0,  447,    2, 0x02,  104 /* Public */,

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
      73, QMetaType::Bool, 0x00015103, uint(4), 0,
      74, QMetaType::QString, 0x00015001, uint(5), 0,

       0        // eod
};

Q_CONSTINIT const QMetaObject IpcBridge::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_IpcBridge.offsetsAndSizes,
    qt_meta_data_IpcBridge,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_IpcBridge_t,
        // property 'expertMode'
        QtPrivate::TypeAndForceComplete<bool, std::true_type>,
        // property 'status'
        QtPrivate::TypeAndForceComplete<QString, std::true_type>,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<IpcBridge, std::true_type>,
        // method 'certificatesLoaded'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QVariantList, std::false_type>,
        // method 'signingFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'verificationFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<QVariantMap, std::false_type>,
        // method 'backendLogReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'expertModeChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'statusChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'serviceStatusReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'serviceActionFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'settingsLoaded'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QVariantMap, std::false_type>,
        // method 'pdfPreviewReceived'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<double, std::false_type>,
        QtPrivate::TypeAndForceComplete<double, std::false_type>,
        // method 'certificateImportFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'publicRootsInstallationFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        // method 'onReadyRead'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onConnected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onError'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QLocalSocket::LocalSocketError, std::false_type>,
        // method 'startBackend'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'startBackend'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'startBackend'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'startBackend'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'startBackend'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'stopBackend'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'canStopOwnedBackend'
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'refreshCertificates'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'signFile'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'signFileAdvanced'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QVariantMap &, std::false_type>,
        // method 'verifyFile'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'updateStatus'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'openExternal'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'openCertManager'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'openLogFolder'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'openHelpManual'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'checkCertificates'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'runTLSDiagnostics'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'exportDiagnosticReport'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'clearTLSTrustStore'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'getServiceStatus'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'installService'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'uninstallService'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'startService'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'stopService'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'getSettings'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'saveSettings'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QVariantMap &, std::false_type>,
        // method 'getPdfPreview'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'getPdfPreview'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'importCertificate'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'installPublicRoots'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void IpcBridge::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<IpcBridge *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->certificatesLoaded((*reinterpret_cast< std::add_pointer_t<QVariantList>>(_a[1]))); break;
        case 1: _t->signingFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 2: _t->verificationFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[3]))); break;
        case 3: _t->backendLogReceived((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 4: _t->expertModeChanged(); break;
        case 5: _t->statusChanged(); break;
        case 6: _t->serviceStatusReceived((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 7: _t->serviceActionFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 8: _t->settingsLoaded((*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[1]))); break;
        case 9: _t->pdfPreviewReceived((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<double>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<double>>(_a[4]))); break;
        case 10: _t->certificateImportFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 11: _t->publicRootsInstallationFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 12: _t->onReadyRead(); break;
        case 13: _t->onConnected(); break;
        case 14: _t->onError((*reinterpret_cast< std::add_pointer_t<QLocalSocket::LocalSocketError>>(_a[1]))); break;
        case 15: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[5]))); break;
        case 16: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 17: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 18: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 19: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 20: _t->stopBackend(); break;
        case 21: { bool _r = _t->canStopOwnedBackend();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 22: _t->refreshCertificates(); break;
        case 23: _t->signFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 24: _t->signFileAdvanced((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[4]))); break;
        case 25: _t->verifyFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 26: _t->updateStatus((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 27: _t->openExternal((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
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
        case 41: _t->saveSettings((*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[1]))); break;
        case 42: _t->getPdfPreview((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[2]))); break;
        case 43: _t->getPdfPreview((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 44: _t->importCertificate((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 45: _t->installPublicRoots(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (IpcBridge::*)(QVariantList );
            if (_t _q_method = &IpcBridge::certificatesLoaded; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString , QString );
            if (_t _q_method = &IpcBridge::signingFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString , QVariantMap );
            if (_t _q_method = &IpcBridge::verificationFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(QString );
            if (_t _q_method = &IpcBridge::backendLogReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)();
            if (_t _q_method = &IpcBridge::expertModeChanged; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)();
            if (_t _q_method = &IpcBridge::statusChanged; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , bool , QString , QString );
            if (_t _q_method = &IpcBridge::serviceStatusReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString );
            if (_t _q_method = &IpcBridge::serviceActionFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(QVariantMap );
            if (_t _q_method = &IpcBridge::settingsLoaded; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString , double , double );
            if (_t _q_method = &IpcBridge::pdfPreviewReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 9;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString );
            if (_t _q_method = &IpcBridge::certificateImportFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 10;
                return;
            }
        }
        {
            using _t = void (IpcBridge::*)(bool , QString );
            if (_t _q_method = &IpcBridge::publicRootsInstallationFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 11;
                return;
            }
        }
    }else if (_c == QMetaObject::ReadProperty) {
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
    } else if (_c == QMetaObject::BindableProperty) {
    }
}

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
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 46;
    }else if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::BindableProperty
            || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    }
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
