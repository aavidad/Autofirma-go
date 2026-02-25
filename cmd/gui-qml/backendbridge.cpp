#include "backendbridge.h"
#include <QClipboard>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
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

void BackendBridge::startBackend(const QString &addr, const QString &token,
                                 const QString &mode,
                                 const QString &fingerprints, bool useTLS) {
  m_addr = addr;
  m_token = token;
  m_useTLS = useTLS;

  if (m_process && m_process->state() != QProcess::NotRunning)
    return;

  QString appDir = QCoreApplication::applicationDirPath();
  QString desktopBin = QDir(appDir).filePath("autofirma-desktop");
  if (!QFileInfo::exists(desktopBin))
    desktopBin = "autofirma-desktop";

  m_process = new QProcess(this);
  m_process->setProgram(desktopBin);

  QStringList args;
  args << "--server" << "--server-modo" << mode << "--rest-addr" << m_addr;
  if (!m_token.isEmpty())
    args << "--rest-token" << m_token;
  if (!fingerprints.isEmpty())
    args << "--rest-cert-fingerprints" << fingerprints;
  if (useTLS)
    args << "--rest-tls";

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

void BackendBridge::openExternal(const QString &path) {
  if (path.isEmpty())
    return;
  if (path.startsWith("http://") || path.startsWith("https://")) {
    QDesktopServices::openUrl(QUrl(path));
  } else {
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
  }
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
  QVariantMap options;
  options.insert("format", format);
  signFileAdvanced(inputPath, outputPath, certIndex, options);
}

void BackendBridge::signFileAdvanced(const QString &inputPath,
                                     const QString &outputPath, int certIndex,
                                     const QVariantMap &options) {
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
  const QString action = options.value("action").toString().trimmed();
  const QString format = options.value("format").toString().trimmed();
  const QString overwrite = options.value("overwrite").toString().trimmed();
  if (!action.isEmpty())
    body.insert("action", action);
  if (!format.isEmpty())
    body.insert("format", format);
  if (!overwrite.isEmpty())
    body.insert("overwrite", overwrite);
  body.insert("allowInvalidPDF",
              options.value("allowInvalidPDF", false).toBool());
  body.insert("strictCompat", options.value("strictCompat", false).toBool());
  body.insert("saveToDisk", options.value("saveToDisk", true).toBool());
  body.insert("returnSignatureB64",
              options.value("returnSignatureB64", false).toBool());

  if (options.contains("visibleSeal")) {
    QVariantMap sealMap = options.value("visibleSeal").toMap();
    if (!sealMap.isEmpty()) {
      QJsonObject seal;
      seal.insert("page", sealMap.value("page", 1).toInt());
      seal.insert("x", sealMap.value("x", 0.62).toDouble());
      seal.insert("y", sealMap.value("y", 0.04).toDouble());
      seal.insert("w", sealMap.value("w", 0.34).toDouble());
      seal.insert("h", sealMap.value("h", 0.12).toDouble());
      body.insert("visibleSeal", seal);
    }
  }

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
  Q_UNUSED(reply);
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
  emit backendLogReceived("⚙ Realizando chequeo exhaustivo de certificados...");
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
      setStatus("Chequeo de certificados finalizado.");
      emit backendLogReceived(
          "ℹ️ Chequeo exhaustivo de certificados completado.");
    } else {
      emit backendLogReceived("Error en chequeo: " + reply->errorString());
      setStatus("Error en chequeo certificados");
    }
    reply->deleteLater();
  });
}

void BackendBridge::runTLSDiagnostics() {
  emit backendLogReceived("⚙ Obteniendo diagnóstico TLS...");
  QUrl url("http://" + m_addr + "/tls/trust-status");
  QNetworkRequest req(url);
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QNetworkReply *reply = m_nam->get(req);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
      QJsonArray lines = doc.object().value("lines").toArray();
      QString msg = "Diagnóstico TLS:\n";
      for (const auto &v : lines)
        msg += v.toString() + "\n";
      emit backendLogReceived(msg);
      setStatus("Diagnóstico TLS finalizado");
    } else {
      emit backendLogReceived("Error al obtener diagnóstico: " +
                              reply->errorString());
    }
    reply->deleteLater();
  });
}

void BackendBridge::exportDiagnosticReport() {
  emit backendLogReceived("⚙ Generando reporte de diagnóstico completo...");
  QUrl url("http://" + m_addr + "/diagnostics/report");
  QNetworkRequest req(url);
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QNetworkReply *reply = m_nam->get(req);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
      QJsonObject res = doc.object();
      emit backendLogReceived(
          QString("Diagnóstico: %1 certs encontrados, %2 válidos para "
                  "firmar.\nAlmacén de confianza: %3 certificados instalados "
                  "en %4.\nRegistro de confianza TLS:\n%5")
              .arg(res.value("certificateCount").toInt())
              .arg(res.value("canSignCount").toInt())
              .arg(res.value("endpointStoreCount").toInt())
              .arg(res.value("endpointStoreDir").toString())
              .arg(res.value("trustStatusLines").toString()));
      setStatus("Diagnóstico completo generado en el log.");
    } else {
      emit backendLogReceived("Error al obtener reporte: " +
                              reply->errorString());
    }
    reply->deleteLater();
  });
}

void BackendBridge::clearTLSTrustStore() {
  emit backendLogReceived("⚙ Vaciando almacén TLS de confianza...");
  QUrl url("http://" + m_addr + "/tls/clear-store");
  QNetworkRequest req(url);
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QNetworkReply *reply = m_nam->post(req, QByteArray());
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
      int removed = doc.object().value("removed").toInt();
      emit backendLogReceived(
          QString("Certificados eliminados del almacén: %1").arg(removed));
      setStatus("Almacén TLS limpiado.");
    } else {
      emit backendLogReceived("Error al vaciar almacén: " +
                              reply->errorString());
    }
    reply->deleteLater();
  });
}

// ─── Service management helpers ──────────────────────────────────────────────

static QNetworkRequest BackendBridgeMakeReq(const QString &addr,
                                            const QString &token,
                                            const QString &path,
                                            bool useTLS = false) {
  QString protocol = useTLS ? "https://" : "http://";
  QNetworkRequest req(QUrl(protocol + addr + path));
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

void BackendBridge::getSettings() {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/settings");
  QNetworkReply *reply = m_nam->get(req);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
      // El backend devuelve { "ok": true, "settings": { ... } }
      emit settingsLoaded(obj.value("settings").toObject().toVariantMap());
    } else {
      emit backendLogReceived("Error al obtener ajustes: " +
                              reply->errorString());
    }
    reply->deleteLater();
  });
}

void BackendBridge::saveSettings(const QVariantMap &settings) {
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/settings");
  QByteArray data = QJsonDocument::fromVariant(settings).toJson();
  QNetworkReply *reply = m_nam->post(req, data);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      emit backendLogReceived("Ajustes guardados correctamente");
      setStatus("Ajustes guardados");
    } else {
      emit backendLogReceived("Error al guardar ajustes: " +
                              reply->errorString());
    }
    reply->deleteLater();
  });
}
void BackendBridge::getPdfPreview(const QString &path, int page) {
  QUrl url("http://" + m_addr + "/pdf/preview");
  QNetworkRequest req(url);
  req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QJsonObject params;
  params.insert("path", path);
  params.insert("page", page);
  QByteArray body = QJsonDocument(params).toJson();

  QNetworkReply *reply = m_nam->post(req, body);
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
      QJsonObject obj = doc.object();
      if (obj.value("ok").toBool()) {
        double w = obj.value("width").toDouble(595.28);
        double h = obj.value("height").toDouble(841.89);
        emit pdfPreviewReceived(true, obj.value("data").toString(), w, h);
      } else {
        emit pdfPreviewReceived(false, obj.value("error").toString(), 0, 0);
      }
    } else {
      emit pdfPreviewReceived(false, reply->errorString(), 0, 0);
    }
    reply->deleteLater();
  });
}

void BackendBridge::installCamerfirmaCerts() {
  if (m_addr.isEmpty()) {
    emit backendLogReceived("❌ No se puede instalar: Backend no configurado.");
    return;
  }

  emit backendLogReceived("🛠 Iniciando instalación de certificados TSA "
                          "públicos (Multi-plataforma)...");

  QUrl url("http://" + m_addr + "/trust/install-public-roots");
  QNetworkRequest req(url);
  req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  if (!m_token.isEmpty())
    req.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());

  QNetworkReply *reply = m_nam->post(req, QByteArray());
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    if (reply->error() == QNetworkReply::NoError) {
      QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
      QJsonObject obj = doc.object();
      if (obj.value("ok").toBool()) {
        QJsonArray lines = obj.value("lines").toArray();
        for (int i = 0; i < lines.size(); ++i) {
          emit backendLogReceived(lines.at(i).toString());
        }
        emit backendLogReceived("✅ Proceso de instalación finalizado.");
        setStatus("Certificados TSA instalados");
      } else {
        emit backendLogReceived("❌ Error: " + obj.value("error").toString());
        setStatus("Error instalando certificados");
      }
    } else {
      emit backendLogReceived("❌ Error de red: " + reply->errorString());
      setStatus("Error de conexión");
    }
    reply->deleteLater();
  });
}

void BackendBridge::importCertificate(const QString &path,
                                      const QString &password) {
  QString localPath = path;
  if (localPath.startsWith("file://")) {
    localPath = QUrl(path).toLocalFile();
  }

  QFile file(localPath);
  if (!file.open(QIODevice::ReadOnly)) {
    emit certificateImportFinished(
        false, "No se pudo abrir el archivo de certificado.");
    return;
  }
  QByteArray data = file.readAll();
  file.close();

  QString b64 = data.toBase64();

  QJsonObject body;
  body.insert("p12B64", b64);
  body.insert("password", password);

  auto req = BackendBridgeMakeReq(m_addr, m_token, "/certificates/import");
  QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson());

  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    bool ok = (reply->error() == QNetworkReply::NoError);
    QString msg = "";
    if (ok) {
      refreshCertificates();
      msg = "Certificado importado correctamente.";
    } else {
      QByteArray response = reply->readAll();
      QJsonDocument doc = QJsonDocument::fromJson(response);
      msg = doc.object().value("error").toString();
      if (msg.isEmpty())
        msg = reply->errorString();
    }
    emit certificateImportFinished(ok, msg);
    reply->deleteLater();
  });
}

void BackendBridge::installPublicRoots() {
  emit backendLogReceived("⚙ Instalando raíces de confianza públicas...");
  auto req = BackendBridgeMakeReq(m_addr, m_token, "/confianza/instalar");
  QNetworkReply *reply = m_nam->post(req, QByteArray());
  connect(reply, &QNetworkReply::finished, this, [this, reply]() {
    bool ok = (reply->error() == QNetworkReply::NoError);
    QString msg = ok ? "Raíces instaladas con éxito" : reply->errorString();
    emit publicRootsInstallationFinished(ok, msg);
    reply->deleteLater();
  });
}
