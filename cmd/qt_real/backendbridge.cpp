#include "backendbridge.h"
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QStandardPaths>
#include <QUrl>
#include <QUrlQuery>

BackendBridge::BackendBridge(QObject *parent) : QObject(parent) {
  m_nam = new QNetworkAccessManager(this);
}

BackendBridge::~BackendBridge() { stopBackend(); }

void BackendBridge::setExpertMode(bool v) {
  if (m_expertMode != v) {
    m_expertMode = v;
    emit expertModeChanged();
  }
}

void BackendBridge::setStatus(const QString &s) {
  if (m_status != s) {
    m_status = s;
    emit statusChanged();
  }
}

void BackendBridge::startBackend(const QString &addr, const QString &token) {
  m_addr = addr;
  m_token = token;

  if (m_process && m_process->state() != QProcess::NotRunning)
    return;

  QString appDir = QCoreApplication::applicationDirPath();
  QString desktopBin = QDir(appDir).filePath("autofirma-desktop");
  if (!QFileInfo::exists(desktopBin))
    desktopBin = "autofirma-desktop";

  m_process = new QProcess(this);
  m_process->setProgram(desktopBin);

  QStringList args;
  args << "--rest" << "--rest-addr" << m_addr;
  if (!m_token.isEmpty())
    args << "--rest-token" << m_token;

  m_process->setArguments(args);
  connect(m_process, &QProcess::readyReadStandardOutput, this,
          &BackendBridge::onBackendReadyRead);
  connect(m_process, &QProcess::readyReadStandardError, this,
          &BackendBridge::onBackendReadyRead);

  m_process->start();
  if (!m_process->waitForStarted(3000)) {
    setStatus("Error al iniciar el backend");
  } else {
    setStatus("Backend activo en " + m_addr);
    refreshCertificates();
  }
}

void BackendBridge::stopBackend() {
  if (m_process) {
    m_process->terminate();
    if (!m_process->waitForFinished(2000))
      m_process->kill();
    m_process->deleteLater();
    m_process = nullptr;
    setStatus("Backend detenido");
  }
}

void BackendBridge::onBackendReadyRead() {
  if (!m_process)
    return;
  QString out = QString::fromUtf8(m_process->readAllStandardOutput());
  QString err = QString::fromUtf8(m_process->readAllStandardError());
  if (!out.isEmpty())
    emit backendLogReceived(out);
  if (!err.isEmpty())
    emit backendLogReceived(err);
}

void BackendBridge::verifyFile(const QString &inputPath) {
  emit backendLogReceived("⚙ Verificando firma de: " + inputPath);
  QUrl url("http://" + m_addr + "/verify");
  QNetworkRequest req(url);
  req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QJsonObject body;
  body.insert("inputPath", inputPath);

  QByteArray jsonData = QJsonDocument(body).toJson();
  QNetworkReply *reply = m_nam->post(req, jsonData);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    bool success = (reply->error() == QNetworkReply::NoError);
    QByteArray dataRaw = reply->readAll();
    QString data = QString::fromUtf8(dataRaw);

    QVariantMap details;
    QString msg = "";

    if (success) {
      QJsonDocument doc = QJsonDocument::fromJson(dataRaw);
      QJsonObject res = doc.object();
      if (res.value("ok").toBool()) {
        QJsonObject result = res.value("result").toObject();
        details = result.toVariantMap();
        bool valid = result.value("valid").toBool();
        msg = valid ? "Firma VÁLIDA"
                    : "Firma NO VÁLIDA: " + result.value("reason").toString();
      } else {
        success = false;
        msg = res.value("error").toString();
      }
    } else {
      msg = "Error de red en verificación: " + reply->errorString();
    }

    emit backendLogReceived("🔍 Respuesta de verificación: " + msg);
    setStatus(msg);
    emit verificationFinished(success, msg, details);
    reply->deleteLater();
  });
}

void BackendBridge::refreshCertificates() {
  emit backendLogReceived("Refrescando certificados...");
  QUrl url("http://" + m_addr + "/certificates?check=1");
  QNetworkRequest req(url);
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QNetworkReply *reply = m_nam->get(req);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QByteArray data = reply->readAll();
      emit backendLogReceived("Respuesta de certificados recibida: " +
                              QString::fromUtf8(data));
      QJsonDocument doc = QJsonDocument::fromJson(data);
      QJsonArray certs = doc.object().value("certificates").toArray();
      QVariantList list;
      for (const auto &c : certs)
        list << c.toVariant();
      emit certificatesLoaded(list);
      setStatus("Certificados actualizados");
    } else {
      QString errorMsg = reply->errorString();
      if (errorMsg.contains("Connection refused"))
        errorMsg = "Conexión rechazada (¿backend activo?)";
      emit backendLogReceived("Error cargando certificados: " + errorMsg);
      setStatus("Error al cargar certificados: " + errorMsg);
    }
    reply->deleteLater();
  });
}

void BackendBridge::signFile(const QString &inputPath,
                             const QString &outputPath, int certIndex,
                             const QString &format) {
  emit backendLogReceived("⚙ Preparando firma de: " + inputPath);
  QUrl url("http://" + m_addr + "/sign");
  QNetworkRequest req(url);
  req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QJsonObject body;
  body.insert("inputPath", inputPath);
  body.insert("outputPath", outputPath);
  body.insert("certificateIndex", certIndex);
  body.insert("format", format);
  body.insert("saveToDisk", true);

  QByteArray jsonData = QJsonDocument(body).toJson();
  emit backendLogReceived("📤 Enviando petición (JSON): " +
                          QString::fromUtf8(jsonData));

  QNetworkReply *reply = m_nam->post(req, jsonData);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    bool success = (reply->error() == QNetworkReply::NoError);
    QByteArray dataRaw = reply->readAll();
    QString data = QString::fromUtf8(dataRaw);
    QString msg = success ? "Firma completada con éxito" : "";

    if (!success) {
      msg = "Error al intentar firmar";
      auto networkErr = reply->error();

      if (networkErr == QNetworkReply::ProtocolInvalidOperationError ||
          networkErr == QNetworkReply::ContentOperationNotPermittedError) {
        msg = "Error 400: Los parámetros enviados no son válidos para el "
              "servidor.";
      } else if (networkErr == QNetworkReply::ConnectionRefusedError) {
        msg = "No se pudo conectar con el servicio local de firma (¿está "
              "bloqueado?).";
      } else if (networkErr == QNetworkReply::HostNotFoundError) {
        msg = "No se encuentra el servidor de firma interno.";
      } else {
        msg = reply->errorString();
        // Traducciones manuales para errores comunes de Qt Network
        if (msg.contains("Connection refused", Qt::CaseInsensitive))
          msg = "Conexión rechazada por el servidor local de firma.";
        else if (msg.contains("Host unreachable", Qt::CaseInsensitive))
          msg = "Servidor de firma no alcanzable en la red local.";
        else if (msg.contains("bad request", Qt::CaseInsensitive))
          msg = "Petición incorrecta: el servidor rechazó los datos (Bad "
                "Request).";
        else if (msg.contains("Error transferring", Qt::CaseInsensitive))
          msg = "Error al transferir datos: el servidor respondió con un error "
                "(posible Bad Request).";
      }
      emit backendLogReceived("❌ ERROR DEL BACKEND: " + data + " | " +
                              reply->errorString());
      setStatus("Error: " + msg);
    }

    QString out = "";
    if (success) {
      out = QJsonDocument::fromJson(dataRaw)
                .object()
                .value("outputPath")
                .toString();
      emit backendLogReceived("✅ Firma guardada exitosamente en: " + out);
      setStatus("Firma completada satisfactoriamente");
    }

    emit signingFinished(success, msg, out);
    reply->deleteLater();
  });
}

void BackendBridge::onNetworkReplyFinished(QNetworkReply *reply) {
  // General handler if needed
}

void BackendBridge::openCertManager() {
#ifdef Q_OS_WIN
  QProcess::startDetached("rundll32.exe", {"cryptext.dll,CryptExtOpenCER"});
#else
  setStatus("Por favor, use el gestor de su sistema o navegador.");
#endif
}

void BackendBridge::openLogFolder() {
  QString path =
      QDir(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation))
          .filePath("logs");
  QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

void BackendBridge::openHelpManual() {
  // Try local manual first
  QString appDir = QCoreApplication::applicationDirPath();
  QString manual = QDir(appDir).filePath("ayuda.pdf");
  if (QFile::exists(manual)) {
    QDesktopServices::openUrl(QUrl::fromLocalFile(manual));
  } else {
    QDesktopServices::openUrl(QUrl("https://autofirma.dipgra.es/manual"));
  }
}

void BackendBridge::checkCertificates() {
  refreshCertificates(); // Basic check
}

void BackendBridge::runTLSDiagnostics() {
  setStatus("Diagnóstico TLS no disponible en este modo.");
}

void BackendBridge::exportDiagnosticReport() {
  setStatus("Exportación de diagnóstico no implementada.");
}

void BackendBridge::clearTLSTrustStore() {
  setStatus("Almacén TLS no gestionado en este modo.");
}

// ─── Service management helpers ──────────────────────────────────────────────

static QNetworkRequest BackendBridgeMakeReq(const QString &addr,
                                            const QString &token,
                                            const QString &path) {
  QNetworkRequest req(QUrl("http://" + addr + path));
  req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  if (!token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + token.toUtf8());
  return req;
}

void BackendBridge::getServiceStatus() {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/service/status");
  QNetworkReply *reply = m_nam->get(req);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
    bool installed = obj.value("status").toObject().value("installed").toBool();
    bool running = obj.value("status").toObject().value("running").toBool();
    QString platform =
        obj.value("status").toObject().value("platform").toString();
    QString method = obj.value("status").toObject().value("method").toString();
    emit serviceStatusReceived(installed, running, platform, method);
    reply->deleteLater();
  });
}

void BackendBridge::installService() {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/service/install");
  QNetworkReply *reply = m_nam->post(req, QByteArray("{}"));
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
    bool ok = obj.value("ok").toBool();
    QString msg = obj.value("message").toString();
    if (!ok)
      msg = obj.value("error").toString();
    emit serviceActionFinished(ok, msg);
    reply->deleteLater();
  });
}

void BackendBridge::uninstallService() {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/service/uninstall");
  QNetworkReply *reply = m_nam->post(req, QByteArray("{}"));
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
    bool ok = obj.value("ok").toBool();
    QString msg =
        ok ? obj.value("message").toString() : obj.value("error").toString();
    emit serviceActionFinished(ok, msg);
    reply->deleteLater();
  });
}

void BackendBridge::startService() {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/service/start");
  QNetworkReply *reply = m_nam->post(req, QByteArray("{}"));
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
    bool ok = obj.value("ok").toBool();
    QString msg =
        ok ? obj.value("message").toString() : obj.value("error").toString();
    emit serviceActionFinished(ok, msg);
    reply->deleteLater();
  });
}

void BackendBridge::stopService() {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/service/stop");
  QNetworkReply *reply = m_nam->post(req, QByteArray("{}"));
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
    bool ok = obj.value("ok").toBool();
    QString msg =
        ok ? obj.value("message").toString() : obj.value("error").toString();
    emit serviceActionFinished(ok, msg);
    reply->deleteLater();
  });
}
