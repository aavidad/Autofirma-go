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
    uint offsetsAndSizes[138];
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
    char stringdata27[12];
    char stringdata28[12];
    char stringdata29[8];
    char stringdata30[31];
    char stringdata31[6];
    char stringdata32[13];
    char stringdata33[5];
    char stringdata34[6];
    char stringdata35[5];
    char stringdata36[13];
    char stringdata37[7];
    char stringdata38[12];
    char stringdata39[20];
    char stringdata40[9];
    char stringdata41[10];
    char stringdata42[10];
    char stringdata43[7];
    char stringdata44[17];
    char stringdata45[8];
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
    char stringdata67[11];
    char stringdata68[7];
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
        QT_MOC_LITERAL(305, 11),  // "onReadyRead"
        QT_MOC_LITERAL(317, 11),  // "onConnected"
        QT_MOC_LITERAL(329, 7),  // "onError"
        QT_MOC_LITERAL(337, 30),  // "QLocalSocket::LocalSocketError"
        QT_MOC_LITERAL(368, 5),  // "error"
        QT_MOC_LITERAL(374, 12),  // "startBackend"
        QT_MOC_LITERAL(387, 4),  // "addr"
        QT_MOC_LITERAL(392, 5),  // "token"
        QT_MOC_LITERAL(398, 4),  // "mode"
        QT_MOC_LITERAL(403, 12),  // "fingerprints"
        QT_MOC_LITERAL(416, 6),  // "useTLS"
        QT_MOC_LITERAL(423, 11),  // "stopBackend"
        QT_MOC_LITERAL(435, 19),  // "refreshCertificates"
        QT_MOC_LITERAL(455, 8),  // "signFile"
        QT_MOC_LITERAL(464, 9),  // "inputPath"
        QT_MOC_LITERAL(474, 9),  // "certIndex"
        QT_MOC_LITERAL(484, 6),  // "format"
        QT_MOC_LITERAL(491, 16),  // "signFileAdvanced"
        QT_MOC_LITERAL(508, 7),  // "options"
        QT_MOC_LITERAL(516, 10),  // "verifyFile"
        QT_MOC_LITERAL(527, 12),  // "updateStatus"
        QT_MOC_LITERAL(540, 3),  // "msg"
        QT_MOC_LITERAL(544, 12),  // "openExternal"
        QT_MOC_LITERAL(557, 4),  // "path"
        QT_MOC_LITERAL(562, 15),  // "openCertManager"
        QT_MOC_LITERAL(578, 13),  // "openLogFolder"
        QT_MOC_LITERAL(592, 14),  // "openHelpManual"
        QT_MOC_LITERAL(607, 17),  // "checkCertificates"
        QT_MOC_LITERAL(625, 17),  // "runTLSDiagnostics"
        QT_MOC_LITERAL(643, 22),  // "exportDiagnosticReport"
        QT_MOC_LITERAL(666, 18),  // "clearTLSTrustStore"
        QT_MOC_LITERAL(685, 16),  // "getServiceStatus"
        QT_MOC_LITERAL(702, 14),  // "installService"
        QT_MOC_LITERAL(717, 16),  // "uninstallService"
        QT_MOC_LITERAL(734, 12),  // "startService"
        QT_MOC_LITERAL(747, 11),  // "stopService"
        QT_MOC_LITERAL(759, 11),  // "getSettings"
        QT_MOC_LITERAL(771, 12),  // "saveSettings"
        QT_MOC_LITERAL(784, 13),  // "getPdfPreview"
        QT_MOC_LITERAL(798, 4),  // "page"
        QT_MOC_LITERAL(803, 10),  // "expertMode"
        QT_MOC_LITERAL(814, 6)   // "status"
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
      41,   14, // methods
       2,  401, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      10,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,  260,    2, 0x06,    3 /* Public */,
       4,    3,  263,    2, 0x06,    5 /* Public */,
       8,    3,  270,    2, 0x06,    9 /* Public */,
      10,    1,  277,    2, 0x06,   13 /* Public */,
      12,    0,  280,    2, 0x06,   15 /* Public */,
      13,    0,  281,    2, 0x06,   16 /* Public */,
      14,    4,  282,    2, 0x06,   17 /* Public */,
      19,    2,  291,    2, 0x06,   22 /* Public */,
      21,    1,  296,    2, 0x06,   25 /* Public */,
      23,    4,  299,    2, 0x06,   27 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      27,    0,  308,    2, 0x08,   32 /* Private */,
      28,    0,  309,    2, 0x08,   33 /* Private */,
      29,    1,  310,    2, 0x08,   34 /* Private */,

 // methods: name, argc, parameters, tag, flags, initial metatype offsets
      32,    5,  313,    2, 0x02,   36 /* Public */,
      32,    4,  324,    2, 0x22,   42 /* Public | MethodCloned */,
      32,    3,  333,    2, 0x22,   47 /* Public | MethodCloned */,
      32,    2,  340,    2, 0x22,   51 /* Public | MethodCloned */,
      32,    1,  345,    2, 0x22,   54 /* Public | MethodCloned */,
      38,    0,  348,    2, 0x02,   56 /* Public */,
      39,    0,  349,    2, 0x02,   57 /* Public */,
      40,    4,  350,    2, 0x02,   58 /* Public */,
      44,    4,  359,    2, 0x02,   63 /* Public */,
      46,    1,  368,    2, 0x02,   68 /* Public */,
      47,    1,  371,    2, 0x02,   70 /* Public */,
      49,    1,  374,    2, 0x02,   72 /* Public */,
      51,    0,  377,    2, 0x02,   74 /* Public */,
      52,    0,  378,    2, 0x02,   75 /* Public */,
      53,    0,  379,    2, 0x02,   76 /* Public */,
      54,    0,  380,    2, 0x02,   77 /* Public */,
      55,    0,  381,    2, 0x02,   78 /* Public */,
      56,    0,  382,    2, 0x02,   79 /* Public */,
      57,    0,  383,    2, 0x02,   80 /* Public */,
      58,    0,  384,    2, 0x02,   81 /* Public */,
      59,    0,  385,    2, 0x02,   82 /* Public */,
      60,    0,  386,    2, 0x02,   83 /* Public */,
      61,    0,  387,    2, 0x02,   84 /* Public */,
      62,    0,  388,    2, 0x02,   85 /* Public */,
      63,    0,  389,    2, 0x02,   86 /* Public */,
      64,    1,  390,    2, 0x02,   87 /* Public */,
      65,    2,  393,    2, 0x02,   89 /* Public */,
      65,    1,  398,    2, 0x22,   92 /* Public | MethodCloned */,

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

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 30,   31,

 // methods: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::Bool,   33,   34,   35,   36,   37,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString, QMetaType::QString,   33,   34,   35,   36,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString,   33,   34,   35,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   33,   34,
    QMetaType::Void, QMetaType::QString,   33,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QString,   41,    7,   42,   43,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Int, QMetaType::QVariantMap,   41,    7,   42,   45,
    QMetaType::Void, QMetaType::QString,   41,
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

 // properties: name, type, flags
      67, QMetaType::Bool, 0x00015103, uint(4), 0,
      68, QMetaType::QString, 0x00015001, uint(5), 0,

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
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>
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
        case 10: _t->onReadyRead(); break;
        case 11: _t->onConnected(); break;
        case 12: _t->onError((*reinterpret_cast< std::add_pointer_t<QLocalSocket::LocalSocketError>>(_a[1]))); break;
        case 13: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4])),(*reinterpret_cast< std::add_pointer_t<bool>>(_a[5]))); break;
        case 14: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 15: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        case 16: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 17: _t->startBackend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 18: _t->stopBackend(); break;
        case 19: _t->refreshCertificates(); break;
        case 20: _t->signFile((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        case 21: _t->signFileAdvanced((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QVariantMap>>(_a[4]))); break;
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
        if (_id < 41)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 41;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 41)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 41;
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
