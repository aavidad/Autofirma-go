#include "ipcbridge.h"
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QVariantMap>

IpcBridge::IpcBridge(QObject *parent) : QObject(parent) {
  m_socket = new QLocalSocket(this);
  connect(m_socket, &QLocalSocket::readyRead, this, &IpcBridge::onReadyRead);
  connect(m_socket, &QLocalSocket::connected, this, &IpcBridge::onConnected);
  connect(m_socket, &QLocalSocket::errorOccurred, this, &IpcBridge::onError);
}

IpcBridge::~IpcBridge() { stopBackend(); }

void IpcBridge::setExpertMode(bool v) {
  if (m_expertMode != v) {
    m_expertMode = v;
    emit expertModeChanged();
  }
}

void IpcBridge::startBackend(const QString &socketPath) {
  m_socketPath = socketPath;

  // If already connected, do nothing
  if (m_socket->state() == QLocalSocket::ConnectedState)
    return;

  // Check if socket file exists — if not, launch the Go backend
  if (!QFileInfo::exists(socketPath)) {
    emit backendLogReceived("Socket no encontrado. Arrancando backend Go...");
    launchBackendProcess();
  } else {
    emit backendLogReceived("Socket encontrado. Conectando...");
  }

  // Try to connect, with automatic retry
  tryConnect();
}

void IpcBridge::launchBackendProcess() {
  if (m_process && m_process->state() != QProcess::NotRunning)
    return;

  // Find autofirma-desktop binary
  QString appDir = QCoreApplication::applicationDirPath();
  QStringList candidates = {
      QDir(appDir).filePath("autofirma-desktop"),
      QDir(appDir).filePath("../autofirma-desktop"),
      QStandardPaths::findExecutable("autofirma-desktop"),
  };
  QString bin;
  for (const auto &c : candidates) {
    if (!c.isEmpty() && QFileInfo::exists(c)) {
      bin = c;
      break;
    }
  }
  if (bin.isEmpty())
    bin = "autofirma-desktop"; // fallback to PATH

  m_process = new QProcess(this);
  m_process->setProgram(bin);
  m_process->setArguments({"--ipc", "--ipc-socket", m_socketPath});
  connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() {
    emit backendLogReceived(
        QString::fromUtf8(m_process->readAllStandardOutput()).trimmed());
  });
  connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
    emit backendLogReceived(
        QString::fromUtf8(m_process->readAllStandardError()).trimmed());
  });
  m_process->start();
  if (!m_process->waitForStarted(3000)) {
    emit backendLogReceived("❌ No se pudo arrancar autofirma-desktop: " +
                            m_process->errorString());
    setStatus("Error al arrancar el backend");
  } else {
    emit backendLogReceived("✅ Backend Go arrancado (PID " +
                            QString::number(m_process->processId()) + ")");
  }
}

void IpcBridge::tryConnect() {
  if (m_socket->state() == QLocalSocket::ConnectedState)
    return;
  m_socket->connectToServer(m_socketPath);

  // If not connected within 500ms, retry (up to 20 times = 10s)
  if (m_retryCount < 20) {
    m_retryCount++;
    QTimer::singleShot(500, this, [this]() {
      if (m_socket->state() != QLocalSocket::ConnectedState) {
        emit backendLogReceived("Reintentando conexión IPC... (" +
                                QString::number(m_retryCount) + "/20)");
        tryConnect();
      }
    });
  } else {
    setStatus("No se pudo conectar al backend tras 10 segundos");
  }
}

void IpcBridge::stopBackend() {
  if (m_socket->isOpen()) {
    m_socket->close();
  }
}

void IpcBridge::refreshCertificates() {
  emit backendLogReceived("🔄 Solicitando certificados vía IPC...");
  sendRequest("certificates");
}

void IpcBridge::signFile(const QString &inputPath, const QString &outputPath,
                         int certIndex, const QString &format) {
  emit backendLogReceived("⚙ Iniciando firma IPC para: " + inputPath);
  QVariantMap params;
  params["inputPath"] = inputPath;
  params["outputPath"] = outputPath;
  params["certificateIndex"] = certIndex;
  params["format"] = format;
  sendRequest("sign", params);
}

void IpcBridge::verifyFile(const QString &inputPath) {
  emit backendLogReceived("🔍 Solicitando verificación IPC para: " + inputPath);
  QVariantMap params;
  params["inputPath"] = inputPath;
  sendRequest("verify", params);
}

void IpcBridge::onConnected() {
  emit backendLogReceived("✅ Conexión establecida con el motor de firma.");
  setStatus("Conectado vía IPC");
  refreshCertificates();
}

void IpcBridge::onError(QLocalSocket::LocalSocketError error) {
  QString errStr = m_socket->errorString();
  emit backendLogReceived("❌ Error en Socket: " + errStr);
  setStatus("Error IPC: " + errStr);
}

void IpcBridge::onReadyRead() {
  while (m_socket->canReadLine()) {
    QByteArray line = m_socket->readLine();
    QJsonDocument doc = QJsonDocument::fromJson(line);
    if (doc.isNull())
      continue;

    QJsonObject obj = doc.object();
    bool ok = obj.value("ok").toBool();
    QString err = obj.value("error").toString();

    if (!ok) {
      emit backendLogReceived("❌ ERROR IPC: " + err);
      emit signingFinished(false, err, "");
      continue;
    }

    QJsonValue data = obj.value("data");
    // Aquí discerniríamos por el tipo de respuesta (podríamos añadir 'action'
    // en la respuesta Go) Por ahora lo hacemos por contenido:
    if (data.isArray()) {
      QVariantList certs;
      QJsonArray arr = data.toArray();
      for (const auto &v : arr)
        certs << v.toVariant();
      emit certificatesLoaded(certs);
      setStatus("Certificados cargados vía IPC");
    } else if (data.isObject()) {
      QJsonObject res = data.toObject();
      if (res.contains("OutputPath")) {
        QString out = res.value("OutputPath").toString();
        emit backendLogReceived("✅ Firma completada. Archivo: " + out);
        emit signingFinished(true, "Firma completada con éxito", out);
      } else if (res.contains("valid")) {
        // Respuesta de verificación
        bool valid = res.value("valid").toBool();
        QString msg =
            valid ? "Firma VÁLIDA"
                  : "Firma NO VÁLIDA: " + res.value("reason").toString();
        emit backendLogReceived("🔍 " + msg);
        setStatus(msg);
        emit verificationFinished(true, msg, res.toVariantMap());
      }
    }
  }
}

void IpcBridge::sendRequest(const QString &action, const QVariantMap &params) {
  if (!m_socket->isOpen()) {
    emit backendLogReceived("⚠️ No hay conexión con el motor.");
    return;
  }
  QJsonObject req;
  req.insert("action", action);
  req.insert("params", QJsonObject::fromVariantMap(params));

  QByteArray data = QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n";
  m_socket->write(data);
}

void IpcBridge::openCertManager() {
#ifdef Q_OS_WIN
  QProcess::startDetached("rundll32.exe", {"cryptext.dll,CryptExtOpenCER"});
#else
  setStatus("Por favor, use el gestor de su sistema o navegador.");
#endif
}

void IpcBridge::openLogFolder() {
  QString path =
      QDir(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation))
          .filePath("logs");
  QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

void IpcBridge::openHelpManual() {
  QString appDir = QCoreApplication::applicationDirPath();
  QString manual = QDir(appDir).filePath("ayuda.pdf");
  if (QFile::exists(manual)) {
    QDesktopServices::openUrl(QUrl::fromLocalFile(manual));
  } else {
    QDesktopServices::openUrl(QUrl("https://autofirma.dipgra.es/manual"));
  }
}

void IpcBridge::checkCertificates() { refreshCertificates(); }

void IpcBridge::runTLSDiagnostics() {
  setStatus("Diagnóstico TLS no disponible en este modo.");
}

void IpcBridge::exportDiagnosticReport() {
  setStatus("Exportación de diagnóstico no implementada.");
}

void IpcBridge::clearTLSTrustStore() {
  setStatus("Almacén TLS no gestionado en este modo.");
}
