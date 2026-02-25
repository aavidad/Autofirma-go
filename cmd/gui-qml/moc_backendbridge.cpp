/****************************************************************************
** Meta object code from reading C++ file 'backendbridge.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "backendbridge.h"
#include <QtNetwork/QSslError>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'backendbridge.h' doesn't include <QObject>."
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
struct qt_meta_stringdata_BackendBridge_t {
    uint offsetsAndSizes[150];
    char stringdata0[14];
    char stringdata1[14];
    char stringdata2[1];
    char stringdata3[18];
    char stringdata4[19];
    char stringdata5[6];
    char stringdata6[16];
    char stringdata7[8];
    char stringdata8[8];
    char stringdata9[11];
    char stringdata10[21];
    char stringdata11[8];
    char stringdata12[19];
    char stringdata13[4];
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
    char stringdata29[19];
    char stringdata30[23];
    char stringdata31[15];
    char stringdata32[6];
    char stringdata33[13];
    char stringdata34[5];
    char stringdata35[6];
    char stringdata36[5];
    char stringdata37[13];
    char stringdata38[7];
    char stringdata39[12];
    char stringdata40[9];
    char stringdata41[10];
    char stringdata42[10];
    char stringdata43[7];
    char stringdata44[17];
    char stringdata45[8];
    char stringdata46[20];
    char stringdata47[11];
    char stringdata48[13];
    char stringdata49[4];
    char stringdata50[13];
    char stringdata51[5];
    char stringdata52[16];
    char stringdata53[14];
    char stringdata54[15];
    char stringdata55[18];
    char stringdata56[18];
    char stringdata57[23];
    char stringdata58[19];
    char stringdata59[17];
    char stringdata60[15];
    char stringdata61[17];
    char stringdata62[13];
    char stringdata63[12];
    char stringdata64[12];
    char stringdata65[13];
    char stringdata66[14];
    char stringdata67[5];
    char stringdata68[23];
    char stringdata69[18];
    char stringdata70[9];
    char stringdata71[19];
    char stringdata72[14];
    char stringdata73[7];
    char stringdata74[11];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_BackendBridge_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_BackendBridge_t qt_meta_stringdata_BackendBridge = {
    {
        QT_MOC_LITERAL(0, 13),  // "BackendBridge"
        QT_MOC_LITERAL(14, 13),  // "statusChanged"
        QT_MOC_LITERAL(28, 0),  // ""
        QT_MOC_LITERAL(29, 17),  // "expertModeChanged"
        QT_MOC_LITERAL(47, 18),  // "certificatesLoaded"
        QT_MOC_LITERAL(66, 5),  // "certs"
        QT_MOC_LITERAL(72, 15),  // "signingFinished"
        QT_MOC_LITERAL(88, 7),  // "success"
        QT_MOC_LITERAL(96, 7),  // "message"
        QT_MOC_LITERAL(104, 10),  // "outputPath"
        QT_MOC_LITERAL(115, 20),  // "verificationFinished"
        QT_MOC_LITERAL(136, 7),  // "details"
        QT_MOC_LITERAL(144, 18),  // "backendLogReceived"
        QT_MOC_LITERAL(163, 3),  // "log"
        QT_MOC_LITERAL(167, 21),  // "serviceStatusReceived"
        QT_MOC_LITERAL(189, 9),  // "installed"
        QT_MOC_LITERAL(199, 7),  // "running"
        QT_MOC_LITERAL(207, 8),  // "platform"
        QT_MOC_LITERAL(216, 6),  // "method"
        QT_MOC_LITERAL(223, 21),  // "serviceActionFinished"
        QT_MOC_LITERAL(245, 2),  // "ok"
        QT_MOC_LITERAL(248, 14),  // "settingsLoaded"
        QT_MOC_LITERAL(263, 8),  // "settings"
        QT_MOC_LITERAL(272, 18),  // "pdfPreviewReceived"
        QT_MOC_LITERAL(291, 4),  // "data"
        QT_MOC_LITERAL(296, 5),  // "width"
        QT_MOC_LITERAL(302, 6),  // "height"
        QT_MOC_LITERAL(309, 25),  // "certificateImportFinished"
        QT_MOC_LITERAL(335, 31),  // "publicRootsInstallationFinished"
        QT_MOC_LITERAL(367, 18),  // "onBackendReadyRead"
        QT_MOC_LITERAL(386, 22),  // "onNetworkReplyFinished"
        QT_MOC_LITERAL(409, 14),  // "QNetworkReply*"
        QT_MOC_LITERAL(424, 5),  // "reply"
        QT_MOC_LITERAL(430, 12),  // "startBackend"
        QT_MOC_LITERAL(443, 4),  // "addr"
        QT_MOC_LITERAL(448, 5),  // "token"
        QT_MOC_LITERAL(454, 4),  // "mode"
        QT_MOC_LITERAL(459, 12),  // "fingerprints"
        QT_MOC_LITERAL(472, 6),  // "useTLS"
        QT_MOC_LITERAL(479, 11),  // "stopBackend"
        QT_MOC_LITERAL(491, 8),  // "signFile"
        QT_MOC_LITERAL(500, 9),  // "inputPath"
        QT_MOC_LITERAL(510, 9),  // "certIndex"
        QT_MOC_LITERAL(520, 6),  // "format"
        QT_MOC_LITERAL(527, 16),  // "signFileAdvanced"
        QT_MOC_LITERAL(544, 7),  // "options"
        QT_MOC_LITERAL(552, 19),  // "refreshCertificates"
        QT_MOC_LITERAL(572, 10),  // "verifyFile"
        QT_MOC_LITERAL(583, 12),  // "updateStatus"
        QT_MOC_LITERAL(596, 3),  // "msg"
        QT_MOC_LITERAL(600, 12),  // "openExternal"
        QT_MOC_LITERAL(613, 4),  // "path"
        QT_MOC_LITERAL(618, 15),  // "openCertManager"
        QT_MOC_LITERAL(634, 13),  // "openLogFolder"
        QT_MOC_LITERAL(648, 14),  // "openHelpManual"
        QT_MOC_LITERAL(663, 17),  // "checkCertificates"
        QT_MOC_LITERAL(681, 17),  // "runTLSDiagnostics"
        QT_MOC_LITERAL(699, 22),  // "exportDiagnosticReport"
        QT_MOC_LITERAL(722, 18),  // "clearTLSTrustStore"
        QT_MOC_LITERAL(741, 16),  // "getServiceStatus"
        QT_MOC_LITERAL(758, 14),  // "installService"
        QT_MOC_LITERAL(773, 16),  // "uninstallService"
        QT_MOC_LITERAL(790, 12),  // "startService"
        QT_MOC_LITERAL(803, 11),  // "stopService"
        QT_MOC_LITERAL(815, 11),  // "getSettings"
        QT_MOC_LITERAL(827, 12),  // "saveSettings"
        QT_MOC_LITERAL(840, 13),  // "getPdfPreview"
        QT_MOC_LITERAL(854, 4),  // "page"
        QT_MOC_LITERAL(859, 22),  // "installCamerfirmaCerts"
        QT_MOC_LITERAL(882, 17),  // "importCertificate"
        QT_MOC_LITERAL(900, 8),  // "password"
        QT_MOC_LITERAL(909, 18),  // "installPublicRoots"
        QT_MOC_LITERAL(928, 13),  // "getAppDirPath"
        QT_MOC_LITERAL(942, 6),  // "status"
        QT_MOC_LITERAL(949, 10)   // "expertMode"
    },
    "BackendBridge",
    "statusChanged",
    "",
    "expertModeChanged",
    "certificatesLoaded",
    "certs",
    "signingFinished",
    "success",
    "message",
    "outputPath",
    "verificationFinished",
    "details",
    "backendLogReceived",
    "log",
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
    "onBackendReadyRead",
    "onNetworkReplyFinished",
    "QNetworkReply*",
    "reply",
    "startBackend",
    "addr",
    "token",
    "mode",
    "fingerprints",
    "useTLS",
    "stopBackend",
    "signFile",
    "inputPath",
    "certIndex",
    "format",
    "signFileAdvanced",
    "options",
    "refreshCertificates",
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
    "installCamerfirmaCerts",
    "importCertificate",
    "password",
    "installPublicRoots",
    "getAppDirPath",
    "status",
    "expertMode"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_BackendBridge[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
      45,   14, // methods
       2,  439, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      12,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,  284,    2, 0x06,    3 /* Public */,
       3,    0,  285,    2, 0x06,    4 /* Public */,
       4,    1,  286,    2, 0x06,    5 /* Public */,
       6,    3,  289,    2, 0x06,    7 /* Public */,
      10,    3,  296,    2, 0x06,   11 /* Public */,
      12,    1,  303,    2, 0x06,   15 /* Public */,
      14,    4,  306,    2, 0x06,   17 /* Public */,
      19,    2,  315,    2, 0x06,   22 /* Public */,
      21,    1,  320,    2, 0x06,   25 /* Public */,
      23,    4,  323,    2, 0x06,   27 /* Public */,
      27,    2,  332,    2, 0x06,   32 /* Public */,
      28,    2,  337,    2, 0x06,   35 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      29,    0,  342,    2, 0x08,   38 /* Private */,
      30,    1,  343,    2, 0x08,   39 /* Private */,

 // methods: name, argc, parameters, tag, flags, initial metatype offsets
      33,    5,  346,    2, 0x02,   41 /* Public */,
      33,    4,  357,    2, 0x22,   47 /* Public | MethodCloned */,
      33,    3,  366,    2, 0x22,   52 /* Public | MethodCloned */,
      33,    2,  373,    2, 0x22,   56 /* Public | MethodCloned */,
      39,    0,  378,    2, 0x02,   59 /* Public */,
      40,    4,  379,    2, 0x02,   60 /* Public */,
      44,    4,  388,    2, 0x02,   65 /* Public */,
      46,    0,  397,    2, 0x02,   70 /* Public */,
      47,    1,  398,    2, 0x02,   71 /* Public */,
      48,    1,  401,    2, 0x02,   73 /* Public */,
      50,    1,  404,    2, 0x02,   75 /* Public */,
      52,    0,  407,    2, 0x02,   77 /* Public */,
      53,    0,  408,    2, 0x02,   78 /* Public */,
      54,    0,  409,    2, 0x02,   79 /* Public */,
      55,    0,  410,    2, 0x02,   80 /* Public */,
      56,    0,  411,    2, 0x02,   81 /* Public */,
      57,    0,  412,    2, 0x02,   82 /* Public */,
      58,    0,  413,    2, 0x02,   83 /* Public */,
      59,    0,  414,    2, 0x02,   84 /* Public */,
      60,    0,  415,    2, 0x02,   85 /* Public */,
      61,    0,  416,    2, 0x02,   86 /* Public */,
      62,    0,  417,    2, 0x02,   87 /* Public */,
      63,    0,  418,    2, 0x02,   88 /* Public */,
      64,    0,  419,    2, 0x02,   89 /* Public */,
      65,    1,  420,    2, 0x02,   90 /* Public */,
      66,    2,  423,    2, 0x02,   92 /* Public */,
      66,    1,  428,    2, 0x22,   95 /* Public | MethodCloned */,
      68,    0,  431,    2, 0x02,   97 /* Public */,
      69,    2,  432,    2, 0x02,   98 /* Public */,
      71,    0,  437,    2, 0x02,  101 /* Public */,
      72,    0,  438,    2, 0x102,  102 /* Public | MethodIsConst  */,

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
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QString,   41,    9,   42,   43,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QVariantMap,   41,    9,   42,   45,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   41,
    QMetaType::Void, QMetaType::QString,   49,
    QMetaType::Void, QMetaType::QString,   51,
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
    QMetaType::Void, QMetaType::QString, QMetaType::Int,   51,   67,
    QMetaType::Void, QMetaType::QString,   51,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   51,   70,
    QMetaType::Void,
    QMetaType::QString,

 // properties: name, type, flags
      73, QMetaType::QString, 0x00015001, uint(0), 0,
      74, QMetaType::Bool, 0x00015103, uint(1), 0,

       0        // eod
};

Q_CONSTINIT const QMetaObject BackendBridge::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_BackendBridge.offsetsAndSizes,
    qt_meta_data_BackendBridge,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_BackendBridge_t,
        // property 'status'
        QtPrivate::TypeAndForceComplete<QString, std::true_type>,
        // property 'expertMode'
        QtPrivate::TypeAndForceComplete<bool, std::true_type>,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<BackendBridge, std::true_type>,
        // method 'statusChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'expertModeChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
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
        // method 'onBackendReadyRead'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onNetworkReplyFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QNetworkReply *, std::false_type>,
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
        // method 'stopBackend'
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
        // method 'refreshCertificates'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
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
        // method 'installCamerfirmaCerts'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'importCertificate'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'installPublicRoots'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'getAppDirPath'
        QtPrivate::TypeAndForceComplete<QString, std::false_type>
    >,
    nullptr
} };

void BackendBridge::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<BackendBridge *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->statusChanged(); break;
        case 1: _t->expertModeChanged(); break;
        case 2: _t->certificatesLoaded((*reinterpret_cast< std::add_pointer_t<QVariantList>>(_a[1]))); break;
        case 3: _t->signingFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 4: _t->verificationFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[3]))); break;
        case 5: _t->backendLogReceived((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 6: _t->serviceStatusReceived((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 7: _t->serviceActionFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 8: _t->settingsLoaded((*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[1]))); break;
        case 9: _t->pdfPreviewReceived((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<double>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<double>>(_a[4]))); break;
        case 10: _t->certificateImportFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 11: _t->publicRootsInstallationFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 12: _t->onBackendReadyRead(); break;
        case 13: _t->onNetworkReplyFinished((*reinterpret_cast< std::add_pointer_t<QNetworkReply*>>(_a[1]))); break;
        case 14: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[5]))); break;
        case 15: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 16: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 17: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 18: _t->stopBackend(); break;
        case 19: _t->signFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 20: _t->signFileAdvanced((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[4]))); break;
        case 21: _t->refreshCertificates(); break;
        case 22: _t->verifyFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 23: _t->updateStatus((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 24: _t->openExternal((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 25: _t->openCertManager(); break;
        case 26: _t->openLogFolder(); break;
        case 27: _t->openHelpManual(); break;
        case 28: _t->checkCertificates(); break;
        case 29: _t->runTLSDiagnostics(); break;
        case 30: _t->exportDiagnosticReport(); break;
        case 31: _t->clearTLSTrustStore(); break;
        case 32: _t->getServiceStatus(); break;
        case 33: _t->installService(); break;
        case 34: _t->uninstallService(); break;
        case 35: _t->startService(); break;
        case 36: _t->stopService(); break;
        case 37: _t->getSettings(); break;
        case 38: _t->saveSettings((*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[1]))); break;
        case 39: _t->getPdfPreview((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[2]))); break;
        case 40: _t->getPdfPreview((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 41: _t->installCamerfirmaCerts(); break;
        case 42: _t->importCertificate((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 43: _t->installPublicRoots(); break;
        case 44: { QString _r = _t->getAppDirPath();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
        case 13:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
            case 0:
                *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType::fromType< QNetworkReply* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (BackendBridge::*)();
            if (_t _q_method = &BackendBridge::statusChanged; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)();
            if (_t _q_method = &BackendBridge::expertModeChanged; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(QVariantList );
            if (_t _q_method = &BackendBridge::certificatesLoaded; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString , QString );
            if (_t _q_method = &BackendBridge::signingFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString , QVariantMap );
            if (_t _q_method = &BackendBridge::verificationFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(QString );
            if (_t _q_method = &BackendBridge::backendLogReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , bool , QString , QString );
            if (_t _q_method = &BackendBridge::serviceStatusReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString );
            if (_t _q_method = &BackendBridge::serviceActionFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(QVariantMap );
            if (_t _q_method = &BackendBridge::settingsLoaded; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString , double , double );
            if (_t _q_method = &BackendBridge::pdfPreviewReceived; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 9;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString );
            if (_t _q_method = &BackendBridge::certificateImportFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 10;
                return;
            }
        }
        {
            using _t = void (BackendBridge::*)(bool , QString );
            if (_t _q_method = &BackendBridge::publicRootsInstallationFinished; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 11;
                return;
            }
        }
    }else if (_c == QMetaObject::ReadProperty) {
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
    } else if (_c == QMetaObject::BindableProperty) {
    }
}

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
        if (_id < 45)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 45;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 45)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 45;
    }else if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::BindableProperty
            || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    }
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
