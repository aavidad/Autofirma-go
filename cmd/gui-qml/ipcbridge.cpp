#include "ipcbridge.h"
#include <QClipboard>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
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
  m_nam = new QNetworkAccessManager(this);
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

void IpcBridge::startBackend(const QString &addr, const QString &token,
                             const QString &mode, const QString &fingerprints,
                             bool useTLS) {
  const QString oldMode = m_serverMode;
  m_addr = addr;
  m_token = token;
  m_serverMode = mode;
  m_fingerprints = fingerprints;
  m_useTLS = useTLS;

  // Determinar ruta del socket de forma segura
  if (m_addr.contains("/") || m_addr.startsWith("\\\\")) {
    m_socketPath = m_addr;
  } else {
    QString userName = QDir::home().dirName();
    if (userName.isEmpty())
      userName = "default";
#if defined(Q_OS_WIN)
    m_socketPath = "\\\\.\\pipe\\autofirma_ipc_" + userName;
#else
    QString runtimeDir =
        QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (runtimeDir.isEmpty())
      runtimeDir = QDir::tempPath();
    m_socketPath = QDir(runtimeDir)
                       .absoluteFilePath("autofirma_ipc_" + userName + ".sock");
#endif
  }
  qDebug() << "[IpcBridge] Calculada m_socketPath:" << m_socketPath;

  // Si ya hay un proceso, detenerlo para asegurar un reinicio limpio
  if (m_process && m_process->state() != QProcess::NotRunning) {
    stopBackend();
    m_process->waitForFinished(2000);
  }

  // Comprobar si el socket esta vivo (solo si no es modo puramente REST)
  bool needsLaunch = true;
  if (m_serverMode != "rest") {
    if (QFileInfo::exists(m_socketPath)) {
      QLocalSocket testSocket;
      testSocket.connectToServer(m_socketPath);
      if (testSocket.waitForConnected(500)) {
        testSocket.disconnectFromServer();
        needsLaunch = false;
        emit backendLogReceived("Socket activo encontrado. Conectando...");
      } else {
        emit backendLogReceived(
            "Socket muerto encontrado. Limpiando y arrancando...");
        QFile::remove(m_socketPath);
      }
    } else {
      emit backendLogReceived("Socket no encontrado. Arrancando backend Go...");
    }
  } else {
    emit backendLogReceived("Modo REST activo. Arrancando backend Go...");
  }

  if (needsLaunch) {
    launchBackendProcess();
  } else {
    tryConnect();
  }
}

void IpcBridge::launchBackendProcess() {
  if (m_process && m_process->state() != QProcess::NotRunning)
    return;

  // Find autofirma-desktop binary
  QString appDir = QCoreApplication::applicationDirPath();
  QStringList candidates = {
      QDir(appDir).filePath("autofirma"),
      QDir(appDir).filePath("../autofirma"),
      QDir(appDir).filePath("../../autofirma"),
      QDir::current().filePath("autofirma"),
      QStandardPaths::findExecutable("autofirma"),
      QDir(appDir).filePath("autofirma-desktop"),
      QDir(appDir).filePath("../autofirma-desktop"),
      QDir(appDir).filePath("../../autofirma-desktop"),
      QDir::current().filePath("autofirma-desktop"),
      QStandardPaths::findExecutable("autofirma-desktop"),
      QDir(appDir).filePath("autofirma-host"),
      QDir(appDir).filePath("../autofirma-host"),
      QDir(appDir).filePath("../../autofirma-host"),
      QDir::current().filePath("autofirma-host"),
      QStandardPaths::findExecutable("autofirma-host"),
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
  QStringList args;
  args << "--server" << "--server-modo" << m_serverMode;
  if (m_serverMode == "rest" || m_serverMode == "ambas") {
    args << "--rest-addr" << m_addr;
    if (!m_token.isEmpty())
      args << "--rest-token" << m_token;
    if (!m_fingerprints.isEmpty())
      args << "--rest-cert-fingerprints" << m_fingerprints;
    if (m_useTLS)
      args << "--rest-tls";
  }
  if (m_serverMode == "ipc" || m_serverMode == "ambas") {
    args << "--ipc-socket" << m_socketPath;
  }

  m_process->setArguments(args);
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
                            QString::number(m_process->processId()) +
                            ") modo [" + m_serverMode + "]");

    if (m_serverMode != "rest") {
      tryConnect();
    } else {
      setStatus("Backend activo (REST)");
      refreshCertificates();
    }
  }
}

void IpcBridge::tryConnect() {
  if (m_socket->state() == QLocalSocket::ConnectedState)
    return;
  if (m_socketPath.isEmpty()) {
    emit backendLogReceived("❌ Error: m_socketPath está vacía.");
    setStatus("Error: Ruta IPC vacía");
    return;
  }
  emit backendLogReceived("🔌 Intentando conectar a: " + m_socketPath);
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
  if (m_process && m_process->state() != QProcess::NotRunning) {
    emit backendLogReceived("🛑 Deteniendo backend...");
    m_process->terminate();
    if (!m_process->waitForFinished(1000)) {
      m_process->kill();
    }
    setStatus("Backend detenido");
  }
}

void IpcBridge::refreshCertificates() {
  QString modeLabel = m_serverMode.toUpper();
  if (modeLabel == "AMBAS")
    modeLabel = "REST+IPC";
  emit backendLogReceived(
      QString("🔄 Solicitando certificados vía %1...").arg(modeLabel));

  if (m_serverMode == "rest") {
    QUrl url("http://" + m_addr + "/certificates?check=1");
    QNetworkRequest req(url);
    if (!m_token.isEmpty())
      req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
      if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonArray certs = doc.object().value("certificates").toArray();
        QVariantList list;
        for (const auto &c : certs)
          list << c.toVariant();
        emit certificatesLoaded(list);
        setStatus("Certificados actualizados (REST)");
      } else {
        emit backendLogReceived("Error REST: " + reply->errorString());
      }
      reply->deleteLater();
    });
  } else {
    sendRequest("certificates");
  }
}

void IpcBridge::signFile(const QString &inputPath, const QString &outputPath,
                         int certIndex, const QString &format) {
  QVariantMap options;
  options["format"] = format;
  signFileAdvanced(inputPath, outputPath, certIndex, options);
}

void IpcBridge::signFileAdvanced(const QString &inputPath,
                                 const QString &outputPath, int certIndex,
                                 const QVariantMap &options) {
  emit backendLogReceived("⚙ Iniciando firma IPC para: " + inputPath);
  QVariantMap params;
  params["inputPath"] = inputPath;
  params["outputPath"] = outputPath;
  params["certificateIndex"] = certIndex;
  params["format"] = options.value("format").toString();
  params["action"] = options.value("action", "sign").toString();
  params["allowInvalidPDF"] = options.value("allowInvalidPDF", false).toBool();
  params["strictCompat"] = options.value("strictCompat", false).toBool();
  params["overwrite"] = options.value("overwrite", "rename").toString();
  params["saveToDisk"] = options.value("saveToDisk", true).toBool();
  params["returnSignatureB64"] =
      options.value("returnSignatureB64", false).toBool();
  if (options.contains("visibleSeal")) {
    params["visibleSeal"] = options.value("visibleSeal").toMap();
  }
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
  Q_UNUSED(error);
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
    QString errMsg = obj.value("error").toString();
    QJsonValue data = obj.value("data");

    // Intentamos obtener la acción del JSON de respuesta (el backend lo añade)
    QString action = obj.value("action").toString();
    if (action.isEmpty()) {
      action = m_pendingAction;
    }
    m_pendingAction.clear();

    // Respuestas de gestion del servicio
    if (action.startsWith("service_")) {
      if (!ok) {
        emit serviceActionFinished(false, errMsg);
      } else if (action == "service_status") {
        // data es un objeto con installed, running, platform, method
        QJsonObject st = data.toObject();
        bool installed = st.value("installed").toBool();
        bool running = st.value("running").toBool();
        QString platform = st.value("platform").toString();
        QString method = st.value("method").toString();
        emit serviceStatusReceived(installed, running, platform, method);
      } else {
        emit serviceActionFinished(true, data.toString());
      }
      continue;
    }

    if (!ok) {
      emit backendLogReceived("Error IPC: " + errMsg);
      emit signingFinished(false, errMsg, "");
      continue;
    }

    // --- LOGICA BASADA EN ACCION (PREFERIDA) ---
    if (action == "pdf_preview") {
      if (ok) {
        QJsonObject res = data.toObject();
        emit pdfPreviewReceived(true, res.value("data").toString(),
                                res.value("width").toDouble(595.28),
                                res.value("height").toDouble(841.89));
      } else {
        emit pdfPreviewReceived(false, errMsg, 0, 0);
      }
      continue;
    }

    if (action == "tls_diagnostics") {
      emit backendLogReceived("Diagnóstico TLS:\n" + data.toString());
      setStatus("Diagnóstico TLS finalizado");
      continue;
    }

    if (action == "clear_tls_trust") {
      emit backendLogReceived(
          QString("Certificados eliminados del almacén: %1").arg(data.toInt()));
      setStatus("Almacén TLS limpiado.");
      continue;
    }

    if (action == "export_diagnostic") {
      QJsonObject res = data.toObject();
      QString report =
          QString("Diagnóstico: %1 certs encontrados, %2 válidos para "
                  "firmar.\nAlmacén de confianza: %3 certificados instalados "
                  "en %4.\nRegistro de confianza TLS:\n%5")
              .arg(res.value("certificates").toInt())
              .arg(res.value("canSign").toInt())
              .arg(res.value("storeCount").toInt())
              .arg(res.value("storeDir").toString())
              .arg(res.value("trustLines").toString());

      emit backendLogReceived(report);
      setStatus("Diagnóstico completo generado en el log.");

      // Copiar al portapapeles automáticamente
      QGuiApplication::clipboard()->setText(report);
      emit backendLogReceived(
          "ℹ️ El reporte de diagnóstico se ha copiado al portapapeles.");
      continue;
    }

    if (action == "get_settings") {
      emit settingsLoaded(data.toObject().toVariantMap());
      setStatus("Configuración cargada");
      continue;
    }

    if (action == "save_settings") {
      emit backendLogReceived("Configuración guardada correctamente");
      setStatus("Configuración guardada");
      continue;
    }

    if (action == "check_certificates") {
      QJsonObject res = data.toObject();
      QVariantList certs;
      QJsonArray arr = res.value("certificates").toArray();
      for (const auto &v : arr)
        certs << v.toVariant();
      emit certificatesLoaded(certs);
      int ok = res.value("okCount").toInt();
      int fail = res.value("failCount").toInt();
      QString msg = QString("Chequeo finalizado: %1 válidos, %2 fallidos.")
                        .arg(ok)
                        .arg(fail);
      setStatus(msg);
      emit backendLogReceived("ℹ️ " + msg);
      continue;
    }

    // --- LOGICA BASADA EN ANALISIS DE TIPO (FALLBACK/GENERAL) ---
    if (data.isArray()) {
      QVariantList certs;
      QJsonArray arr = data.toArray();
      for (const auto &v : arr)
        certs << v.toVariant();
      emit certificatesLoaded(certs);
      setStatus("Certificados cargados");
    } else if (data.isObject()) {
      QJsonObject res = data.toObject();
      if (res.contains("OutputPath")) {
        QString out = res.value("OutputPath").toString();
        emit backendLogReceived("Firma completada: " + out);
        emit signingFinished(true, "Firma completada correctamente", out);
      } else if (res.contains("valid")) {
        bool valid = res.value("valid").toBool();
        QString msg =
            valid ? "Firma valida"
                  : "Firma NO valida: " + res.value("reason").toString();
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

void IpcBridge::openExternal(const QString &path) {
  if (path.isEmpty())
    return;
  if (path.startsWith("http://") || path.startsWith("https://")) {
    QDesktopServices::openUrl(QUrl(path));
  } else {
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
  }
}

void IpcBridge::openCertManager() {
#ifdef Q_OS_WIN
  QProcess::startDetached("rundll32.exe", {"cryptext.dll,CryptExtOpenCER"});
#elif defined(Q_OS_MACOS)
  QProcess::startDetached(
      "open", {"/System/Applications/Utilities/Keychain Access.app"});
#else
  // Linux: intentamos abrir gestores comunes
  bool opened = false;
  QStringList tools = {"seahorse", "kleopatra", "gcr-viewer"};
  for (const QString &tool : tools) {
    if (QProcess::startDetached(tool, {})) {
      opened = true;
      break;
    }
  }
  if (!opened) {
    // Fallback: abrir manual o dar guia
    emit backendLogReceived("ℹ️ No se encontró un gestor de certificados "
                            "nativo (seahorse/kleopatra).");
    setStatus("Abra la configuración de certificados de su navegador.");
    QDesktopServices::openUrl(
        QUrl("https://autofirma.dipgra.es/faq/certificados-linux"));
  }
#endif
}

void IpcBridge::openLogFolder() {
  QString home = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
  // Según defaultLogDir() en applog.go para Linux:
  // filepath.Join(base, "autofirma-dipgra", "logs") donde base es
  // ~/.local/state
  QString path = home + "/.local/state/autofirma-dipgra/logs";

#ifdef Q_OS_WIN
  path = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) +
         "/logs";
#endif

  QDir d(path);
  if (!d.exists()) {
    d.mkpath(".");
  }
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

void IpcBridge::checkCertificates() {
  QString modeLabel = m_serverMode.toUpper();
  if (modeLabel == "AMBAS")
    modeLabel = "REST+IPC";
  emit backendLogReceived(
      QString("⚙ Realizando chequeo exhaustivo de certificados vía %1...")
          .arg(modeLabel));

  if (m_serverMode == "rest") {
    QUrl url("http://" + m_addr + "/certificates?check=true");
    QNetworkRequest req(url);
    if (!m_token.isEmpty())
      req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
      if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonArray certs = doc.object().value("certificates").toArray();
        QVariantList list;
        for (const auto &c : certs)
          list << c.toVariant();
        emit certificatesLoaded(list);
        setStatus("Chequeo finalizado (REST)");
      } else {
        emit backendLogReceived("Error REST: " + reply->errorString());
      }
      reply->deleteLater();
    });
  } else {
    sendRequest("check_certificates");
  }
}

void IpcBridge::runTLSDiagnostics() {
  emit backendLogReceived("⚙ Iniciando diagnóstico TLS (" +
                          m_serverMode.toUpper() + ")...");
  if (m_serverMode == "rest") {
    QUrl url("http://" + m_addr + "/tls/trust-status");
    QNetworkRequest req(url);
    if (!m_token.isEmpty())
      req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
      if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        emit backendLogReceived("Diagnóstico TLS recibido vía REST: " +
                                QString::fromUtf8(data));
      } else {
        emit backendLogReceived("Error diagnóstico TLS (REST): " +
                                reply->errorString());
      }
      reply->deleteLater();
    });
  } else {
    sendRequest("tls_diagnostics", QVariantMap());
  }
}

void IpcBridge::exportDiagnosticReport() {
  sendRequest("export_diagnostic", QVariantMap());
}

void IpcBridge::clearTLSTrustStore() {
  sendRequest("clear_tls_trust", QVariantMap());
}

// ── Gestión del servicio de usuario (via IPC)
// ─────────────────────────────────

void IpcBridge::getServiceStatus() {
  emit backendLogReceived("Consultando estado del servicio...");
  QJsonObject req;
  req.insert("action", "service_status");
  req.insert("params", QJsonObject());
  QByteArray data = QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n";
  if (!m_socket->isOpen()) {
    emit serviceActionFinished(false, "Sin conexión con el motor");
    return;
  }
  // La respuesta la procesa onReadyRead → parseServiceResponse
  m_pendingAction = "service_status";
  m_socket->write(data);
}

void IpcBridge::installService() {
  QJsonObject params;
  params.insert("ipcSocket", m_socketPath);
  QJsonObject req;
  req.insert("action", "service_install");
  req.insert("params", params);
  if (!m_socket->isOpen()) {
    emit serviceActionFinished(false, "Sin conexión");
    return;
  }
  m_pendingAction = "service_install";
  m_socket->write(QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n");
}

void IpcBridge::uninstallService() {
  QJsonObject req;
  req.insert("action", "service_uninstall");
  req.insert("params", QJsonObject());
  if (!m_socket->isOpen()) {
    emit serviceActionFinished(false, "Sin conexión");
    return;
  }
  m_pendingAction = "service_uninstall";
  m_socket->write(QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n");
}

void IpcBridge::startService() {
  QJsonObject req;
  req.insert("action", "service_start");
  req.insert("params", QJsonObject());
  if (!m_socket->isOpen()) {
    emit serviceActionFinished(false, "Sin conexión");
    return;
  }
  m_pendingAction = "service_start";
  m_socket->write(QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n");
}

void IpcBridge::stopService() {
  QJsonObject req;
  req.insert("action", "service_stop");
  req.insert("params", QJsonObject());
  if (!m_socket->isOpen()) {
    emit serviceActionFinished(false, "Sin conexión");
    return;
  }
  m_pendingAction = "service_stop";
  m_socket->write(QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n");
}

void IpcBridge::getSettings() {
  m_pendingAction = "get_settings";
  sendRequest("get_settings");
}

void IpcBridge::saveSettings(const QVariantMap &settings) {
  m_pendingAction = "save_settings";
  sendRequest("save_settings", settings);
}

void IpcBridge::getPdfPreview(const QString &path, int page) {
  QJsonObject params;
  params.insert("path", path);
  params.insert("page", page);
  m_pendingAction = "pdf_preview";

  QJsonObject req;
  req.insert("action", "pdf_preview");
  req.insert("params", params);

  if (!m_socket->isOpen()) {
    emit pdfPreviewReceived(false, "Sin conexión IPC", 0, 0);
    return;
  }
  m_socket->write(QJsonDocument(req).toJson(QJsonDocument::Compact) + "\n");
}
