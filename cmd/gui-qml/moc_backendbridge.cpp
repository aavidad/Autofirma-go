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
    uint offsetsAndSizes[146];
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
    char stringdata28[19];
    char stringdata29[23];
    char stringdata30[15];
    char stringdata31[6];
    char stringdata32[13];
    char stringdata33[5];
    char stringdata34[6];
    char stringdata35[5];
    char stringdata36[13];
    char stringdata37[7];
    char stringdata38[12];
    char stringdata39[9];
    char stringdata40[10];
    char stringdata41[10];
    char stringdata42[7];
    char stringdata43[17];
    char stringdata44[8];
    char stringdata45[20];
    char stringdata46[11];
    char stringdata47[13];
    char stringdata48[4];
    char stringdata49[13];
    char stringdata50[5];
    char stringdata51[16];
    char stringdata52[14];
    char stringdata53[15];
    char stringdata54[18];
    char stringdata55[18];
    char stringdata56[23];
    char stringdata57[19];
    char stringdata58[17];
    char stringdata59[15];
    char stringdata60[17];
    char stringdata61[13];
    char stringdata62[12];
    char stringdata63[12];
    char stringdata64[13];
    char stringdata65[14];
    char stringdata66[5];
    char stringdata67[23];
    char stringdata68[18];
    char stringdata69[9];
    char stringdata70[14];
    char stringdata71[7];
    char stringdata72[11];
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
        QT_MOC_LITERAL(335, 18),  // "onBackendReadyRead"
        QT_MOC_LITERAL(354, 22),  // "onNetworkReplyFinished"
        QT_MOC_LITERAL(377, 14),  // "QNetworkReply*"
        QT_MOC_LITERAL(392, 5),  // "reply"
        QT_MOC_LITERAL(398, 12),  // "startBackend"
        QT_MOC_LITERAL(411, 4),  // "addr"
        QT_MOC_LITERAL(416, 5),  // "token"
        QT_MOC_LITERAL(422, 4),  // "mode"
        QT_MOC_LITERAL(427, 12),  // "fingerprints"
        QT_MOC_LITERAL(440, 6),  // "useTLS"
        QT_MOC_LITERAL(447, 11),  // "stopBackend"
        QT_MOC_LITERAL(459, 8),  // "signFile"
        QT_MOC_LITERAL(468, 9),  // "inputPath"
        QT_MOC_LITERAL(478, 9),  // "certIndex"
        QT_MOC_LITERAL(488, 6),  // "format"
        QT_MOC_LITERAL(495, 16),  // "signFileAdvanced"
        QT_MOC_LITERAL(512, 7),  // "options"
        QT_MOC_LITERAL(520, 19),  // "refreshCertificates"
        QT_MOC_LITERAL(540, 10),  // "verifyFile"
        QT_MOC_LITERAL(551, 12),  // "updateStatus"
        QT_MOC_LITERAL(564, 3),  // "msg"
        QT_MOC_LITERAL(568, 12),  // "openExternal"
        QT_MOC_LITERAL(581, 4),  // "path"
        QT_MOC_LITERAL(586, 15),  // "openCertManager"
        QT_MOC_LITERAL(602, 13),  // "openLogFolder"
        QT_MOC_LITERAL(616, 14),  // "openHelpManual"
        QT_MOC_LITERAL(631, 17),  // "checkCertificates"
        QT_MOC_LITERAL(649, 17),  // "runTLSDiagnostics"
        QT_MOC_LITERAL(667, 22),  // "exportDiagnosticReport"
        QT_MOC_LITERAL(690, 18),  // "clearTLSTrustStore"
        QT_MOC_LITERAL(709, 16),  // "getServiceStatus"
        QT_MOC_LITERAL(726, 14),  // "installService"
        QT_MOC_LITERAL(741, 16),  // "uninstallService"
        QT_MOC_LITERAL(758, 12),  // "startService"
        QT_MOC_LITERAL(771, 11),  // "stopService"
        QT_MOC_LITERAL(783, 11),  // "getSettings"
        QT_MOC_LITERAL(795, 12),  // "saveSettings"
        QT_MOC_LITERAL(808, 13),  // "getPdfPreview"
        QT_MOC_LITERAL(822, 4),  // "page"
        QT_MOC_LITERAL(827, 22),  // "installCamerfirmaCerts"
        QT_MOC_LITERAL(850, 17),  // "importCertificate"
        QT_MOC_LITERAL(868, 8),  // "password"
        QT_MOC_LITERAL(877, 13),  // "getAppDirPath"
        QT_MOC_LITERAL(891, 6),  // "status"
        QT_MOC_LITERAL(898, 10)   // "expertMode"
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
      43,   14, // methods
       2,  421, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      11,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,  272,    2, 0x06,    3 /* Public */,
       3,    0,  273,    2, 0x06,    4 /* Public */,
       4,    1,  274,    2, 0x06,    5 /* Public */,
       6,    3,  277,    2, 0x06,    7 /* Public */,
      10,    3,  284,    2, 0x06,   11 /* Public */,
      12,    1,  291,    2, 0x06,   15 /* Public */,
      14,    4,  294,    2, 0x06,   17 /* Public */,
      19,    2,  303,    2, 0x06,   22 /* Public */,
      21,    1,  308,    2, 0x06,   25 /* Public */,
      23,    4,  311,    2, 0x06,   27 /* Public */,
      27,    2,  320,    2, 0x06,   32 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      28,    0,  325,    2, 0x08,   35 /* Private */,
      29,    1,  326,    2, 0x08,   36 /* Private */,

 // methods: name, argc, parameters, tag, flags, initial metatype offsets
      32,    5,  329,    2, 0x02,   38 /* Public */,
      32,    4,  340,    2, 0x22,   44 /* Public | MethodCloned */,
      32,    3,  349,    2, 0x22,   49 /* Public | MethodCloned */,
      32,    2,  356,    2, 0x22,   53 /* Public | MethodCloned */,
      38,    0,  361,    2, 0x02,   56 /* Public */,
      39,    4,  362,    2, 0x02,   57 /* Public */,
      43,    4,  371,    2, 0x02,   62 /* Public */,
      45,    0,  380,    2, 0x02,   67 /* Public */,
      46,    1,  381,    2, 0x02,   68 /* Public */,
      47,    1,  384,    2, 0x02,   70 /* Public */,
      49,    1,  387,    2, 0x02,   72 /* Public */,
      51,    0,  390,    2, 0x02,   74 /* Public */,
      52,    0,  391,    2, 0x02,   75 /* Public */,
      53,    0,  392,    2, 0x02,   76 /* Public */,
      54,    0,  393,    2, 0x02,   77 /* Public */,
      55,    0,  394,    2, 0x02,   78 /* Public */,
      56,    0,  395,    2, 0x02,   79 /* Public */,
      57,    0,  396,    2, 0x02,   80 /* Public */,
      58,    0,  397,    2, 0x02,   81 /* Public */,
      59,    0,  398,    2, 0x02,   82 /* Public */,
      60,    0,  399,    2, 0x02,   83 /* Public */,
      61,    0,  400,    2, 0x02,   84 /* Public */,
      62,    0,  401,    2, 0x02,   85 /* Public */,
      63,    0,  402,    2, 0x02,   86 /* Public */,
      64,    1,  403,    2, 0x02,   87 /* Public */,
      65,    2,  406,    2, 0x02,   89 /* Public */,
      65,    1,  411,    2, 0x22,   92 /* Public | MethodCloned */,
      67,    0,  414,    2, 0x02,   94 /* Public */,
      68,    2,  415,    2, 0x02,   95 /* Public */,
      70,    0,  420,    2, 0x102,   98 /* Public | MethodIsConst  */,

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

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 30,   31,

 // methods: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::Bool,   33,   34,   35,   36,   37,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString,   33,   34,   35,   36,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString,   33,   34,   35,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   33,   34,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QString,   40,    9,   41,   42,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QVariantMap,   40,    9,   41,   44,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   40,
    QMetaType::Void, QMetaType::QString,   48,
    QMetaType::Void, QMetaType::QString,   50,
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
    QMetaType::Void, QMetaType::QString, QMetaType::Int,   50,   66,
    QMetaType::Void, QMetaType::QString,   50,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   50,   69,
    QMetaType::QString,

 // properties: name, type, flags
      71, QMetaType::QString, 0x00015001, uint(0), 0,
      72, QMetaType::Bool, 0x00015103, uint(1), 0,

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
        case 11: _t->onBackendReadyRead(); break;
        case 12: _t->onNetworkReplyFinished((*reinterpret_cast< std::add_pointer_t<QNetworkReply*>>(_a[1]))); break;
        case 13: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[5]))); break;
        case 14: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 15: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 16: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 17: _t->stopBackend(); break;
        case 18: _t->signFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 19: _t->signFileAdvanced((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[4]))); break;
        case 20: _t->refreshCertificates(); break;
        case 21: _t->verifyFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 22: _t->updateStatus((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 23: _t->openExternal((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 24: _t->openCertManager(); break;
        case 25: _t->openLogFolder(); break;
        case 26: _t->openHelpManual(); break;
        case 27: _t->checkCertificates(); break;
        case 28: _t->runTLSDiagnostics(); break;
        case 29: _t->exportDiagnosticReport(); break;
        case 30: _t->clearTLSTrustStore(); break;
        case 31: _t->getServiceStatus(); break;
        case 32: _t->installService(); break;
        case 33: _t->uninstallService(); break;
        case 34: _t->startService(); break;
        case 35: _t->stopService(); break;
        case 36: _t->getSettings(); break;
        case 37: _t->saveSettings((*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[1]))); break;
        case 38: _t->getPdfPreview((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[2]))); break;
        case 39: _t->getPdfPreview((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 40: _t->installCamerfirmaCerts(); break;
        case 41: _t->importCertificate((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 42: { QString _r = _t->getAppDirPath();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
        case 12:
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
        if (_id < 43)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 43;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 43)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 43;
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
