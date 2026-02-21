#include "backendbridge.h"
#include "ipcbridge.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QObject>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QString>
#include <QUrl>

int main(int argc, char *argv[]) {
  bool useIpc = false;
  for (int i = 1; i < argc; ++i) {
    QString arg = QString::fromLocal8Bit(argv[i]);
    if (arg == "--ipc" || arg == "-ipc")
      useIpc = true;
  }

  QGuiApplication app(argc, argv);
  app.setApplicationName("AutoFirma Dipgra Modern");
  app.setOrganizationName("Diputacion de Granada");

  BackendBridge restBridge;
  IpcBridge ipcBridge;
  QObject *activeBridge = &restBridge;

  // Check if expert mode is in args
  for (int i = 1; i < argc; ++i) {
    QString arg = QString::fromLocal8Bit(argv[i]).toLower();
    if (arg == "--experto" || arg == "-experto") {
      restBridge.setExpertMode(true);
      ipcBridge.setExpertMode(true);
    }
  }

  if (useIpc)
    activeBridge = &ipcBridge;

  QQmlApplicationEngine engine;
  engine.rootContext()->setContextProperty("backend", activeBridge);
  // Expose bridge type for UI info
  engine.rootContext()->setContextProperty("isIpcMode", useIpc);

  // Resolve QML path - always prioritize the QML bundled next to the binary
  QString binDir = QCoreApplication::applicationDirPath();
  QStringList candidates = {
      binDir + "/qml/main.qml",    // standard: next to binary
      binDir + "/../qml/main.qml", // one level up
      QDir::currentPath() +
          "/cmd/qt_real/qml/main.qml",      // dev: run from source root
      binDir + "/cmd/qt_real/qml/main.qml", // dev variant
  };
  QString qmlPath;
  for (const auto &c : candidates) {
    if (QFileInfo::exists(c)) {
      qmlPath = c;
      break;
    }
  }
  if (qmlPath.isEmpty()) {
    qWarning("No se encontró main.qml en ninguna ubicación conocida");
    return -1;
  }
  qDebug() << "Cargando QML desde:" << qmlPath;

  engine.load(QUrl::fromLocalFile(qmlPath));

  if (engine.rootObjects().isEmpty())
    return -1;

  // Start backend automatically based on mode
  if (useIpc) {
    ipcBridge.startBackend("/tmp/autofirma_ipc.sock");
  } else {
    restBridge.startBackend("127.0.0.1:63118", "secreto");
  }

  return app.exec();
}
