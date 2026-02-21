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
  // Por defecto: IPC (socket Unix) — más rápido y seguro para comunicación
  // local. Usa --rest para activar el modo REST HTTP.
  bool useRest = false;
  for (int i = 1; i < argc; ++i) {
    QString arg = QString::fromLocal8Bit(argv[i]);
    if (arg == "--rest" || arg == "-rest")
      useRest = true;
  }
  bool useIpc = !useRest;

  QGuiApplication app(argc, argv);
  app.setApplicationName("AutoFirma Dipgra");
  app.setOrganizationName("Diputacion de Granada");

  BackendBridge restBridge;
  IpcBridge ipcBridge;
  QObject *activeBridge = &ipcBridge; // IPC por defecto

  // Check expert mode arg
  for (int i = 1; i < argc; ++i) {
    QString arg = QString::fromLocal8Bit(argv[i]).toLower();
    if (arg == "--experto" || arg == "-experto") {
      restBridge.setExpertMode(true);
      ipcBridge.setExpertMode(true);
    }
  }

  if (useRest)
    activeBridge = &restBridge;

  QQmlApplicationEngine engine;
  engine.rootContext()->setContextProperty("backend", activeBridge);
  engine.rootContext()->setContextProperty("isIpcMode", useIpc);

  // Resolver ruta QML
  QString binDir = QCoreApplication::applicationDirPath();
  QStringList candidates = {
      binDir + "/qml/main.qml",
      binDir + "/../qml/main.qml",
      QDir::currentPath() + "/cmd/qt_real/qml/main.qml",
      binDir + "/cmd/qt_real/qml/main.qml",
  };
  QString qmlPath;
  for (const auto &c : candidates) {
    if (QFileInfo::exists(c)) {
      qmlPath = c;
      break;
    }
  }
  if (qmlPath.isEmpty()) {
    qWarning("No se encontro main.qml en ninguna ubicacion conocida");
    return -1;
  }
  qDebug() << (useIpc ? "[modo IPC]" : "[modo REST]") << "QML:" << qmlPath;

  engine.load(QUrl::fromLocalFile(qmlPath));
  if (engine.rootObjects().isEmpty())
    return -1;

  // Arrancar backend automaticamente
  if (useIpc) {
    ipcBridge.startBackend("/tmp/autofirma_ipc.sock");
  } else {
    restBridge.startBackend("127.0.0.1:63118", "secreto");
  }

  return app.exec();
}
