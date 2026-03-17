// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QStringList>
#include <QTabWidget>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <functional>

struct EndpointPreset {
  QString name;
  QString method;
  QString path;
  QString body;
};

static QString findDesktopBinary(const QString& appDir) {
  const QString local = QDir(appDir).filePath("autofirma-desktop");
  if (QFileInfo::exists(local) && QFileInfo(local).isExecutable()) {
    return local;
  }
  return QStringLiteral("autofirma-desktop");
}

static QStringList sanitizeArgs(const QStringList& in) {
  QStringList out;
  bool skipNext = false;
  for (const QString& raw : in) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    const QString a = raw.trimmed().toLower();
    if (a == "-qt" || a == "--qt" || a == "-fyne" || a == "--fyne" || a == "-gio" || a == "--gio") {
      continue;
    }
    if (a == "-frontend" || a == "--frontend") {
      skipNext = true;
      continue;
    }
    if (a.startsWith("-frontend=") || a.startsWith("--frontend=")) {
      continue;
    }
    if (a == "--experto" || a == "-experto" || a == "--modo-experto" || a == "-modo-experto") {
      continue;
    }
    out << raw;
  }
  return out;
}

static void configureQtRuntimeEnv(QProcessEnvironment& env, const QString& appDir) {
  QString runtime = env.value("AUTOFIRMA_QT_RUNTIME_DIR").trimmed();
  if (runtime.isEmpty()) {
    const QString localRuntime = QDir(appDir).filePath("qt-runtime");
    if (QFileInfo(localRuntime).isDir()) {
      runtime = localRuntime;
    }
  }
  if (runtime.isEmpty()) {
    return;
  }
  env.insert("AUTOFIRMA_QT_RUNTIME_DIR", runtime);
  const QString plugins = QDir(runtime).filePath("plugins");
  if (QFileInfo(plugins).isDir()) {
    env.insert("QT_PLUGIN_PATH", plugins);
  }
  const QString libDir = QDir(runtime).filePath("lib");
  const QString prev = env.value("LD_LIBRARY_PATH");
  const QString prefix = libDir + ":" + runtime;
  env.insert("LD_LIBRARY_PATH", prev.isEmpty() ? prefix : (prefix + ":" + prev));
}

class MainWindow : public QMainWindow {
public:
  explicit MainWindow(bool expertMode) : expertMode_(expertMode) {
    setWindowTitle(expertMode_ ? "AutoFirma Qt - Modo experto" : "AutoFirma Qt");
    resize(1280, 900);
    initPresets();
    buildUI();
    QTimer::singleShot(500, this, [this]() {
      startBackend();
      QTimer::singleShot(700, this, [this]() {
        quickHealth();
        refreshCertificates();
      });
    });
  }

  ~MainWindow() override {
    stopBackend();
  }

private:
  bool expertMode_ = false;
  QLineEdit* addrEdit_ = nullptr;
  QLineEdit* tokenEdit_ = nullptr;
  QLabel* statusLabel_ = nullptr;
  QProcess* backend_ = nullptr;
  QNetworkAccessManager* nam_ = nullptr;

  QLineEdit* signInputEdit_ = nullptr;
  QLineEdit* signOutputEdit_ = nullptr;
  QComboBox* signFormatCombo_ = nullptr;
  QComboBox* signActionCombo_ = nullptr;
  QComboBox* signCertCombo_ = nullptr;
  QCheckBox* signReturnB64Check_ = nullptr;

  QLineEdit* verifyInputEdit_ = nullptr;
  QLineEdit* verifySigEdit_ = nullptr;
  QLineEdit* verifyOrigEdit_ = nullptr;
  QComboBox* verifyFormatCombo_ = nullptr;

  QComboBox* presetCombo_ = nullptr;
  QComboBox* methodCombo_ = nullptr;
  QLineEdit* pathEdit_ = nullptr;
  QPlainTextEdit* bodyEdit_ = nullptr;

  QPlainTextEdit* responseBox_ = nullptr;
  QPlainTextEdit* backendLogBox_ = nullptr;
  QList<EndpointPreset> presets_;
  QString lastSignedPath_;

  void buildUI() {
    nam_ = new QNetworkAccessManager(this);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);

    auto* topBar = new QHBoxLayout();
    topBar->addStretch(1);
    auto* modeBtn = new QPushButton(expertMode_ ? "Cambiar a modo normal" : "Cambiar a modo experto", central);
    topBar->addWidget(modeBtn);
    root->addLayout(topBar);
    connect(modeBtn, &QPushButton::clicked, this, [this]() { relaunchWithMode(!expertMode_); });

    addrEdit_ = new QLineEdit("127.0.0.1:63118", central);
    tokenEdit_ = new QLineEdit("secreto", central);
    tokenEdit_->setPlaceholderText("Clave de conexión con el servidor REST");
    QPushButton* btnStart = nullptr;
    QPushButton* btnStop = nullptr;
    QPushButton* btnHealth = nullptr;
    QPushButton* btnCerts = nullptr;
    if (expertMode_) {
      auto* connBox = new QGroupBox("Servicio local", central);
      auto* connLayout = new QGridLayout(connBox);
      btnStart = new QPushButton("Iniciar", connBox);
      btnStop = new QPushButton("Parar", connBox);
      btnHealth = new QPushButton("Comprobar salud", connBox);
      btnCerts = new QPushButton("Refrescar certificados", connBox);
      statusLabel_ = new QLabel("Servicio detenido", connBox);

      connLayout->addWidget(new QLabel("Dirección:"), 0, 0);
      connLayout->addWidget(addrEdit_, 0, 1);
      connLayout->addWidget(new QLabel("Clave de conexión REST:"), 0, 2);
      connLayout->addWidget(tokenEdit_, 0, 3);
      auto* tokenHint = new QLabel("Se usa para autorizar las peticiones entre la app y el servidor local.", connBox);
      connLayout->addWidget(tokenHint, 1, 2, 1, 2);
      connLayout->addWidget(btnStart, 2, 0);
      connLayout->addWidget(btnStop, 2, 1);
      connLayout->addWidget(btnHealth, 2, 2);
      connLayout->addWidget(btnCerts, 2, 3);
      connLayout->addWidget(statusLabel_, 3, 0, 1, 4);
      root->addWidget(connBox);
    } else {
      auto* authBox = new QGroupBox("Conexión", central);
      auto* authLayout = new QGridLayout(authBox);
      authLayout->addWidget(new QLabel("Clave de conexión REST:"), 0, 0);
      authLayout->addWidget(tokenEdit_, 0, 1);
      auto* tokenHint = new QLabel("Clave para autorizar la conexión con el servidor local.", authBox);
      authLayout->addWidget(tokenHint, 1, 0, 1, 2);
      root->addWidget(authBox);
    }

    auto* tabs = new QTabWidget(central);
    tabs->addTab(buildSignTab(), "Firmar");
    tabs->addTab(buildVerifyTab(), "Verificar");
    if (expertMode_) {
      tabs->addTab(buildDiagnosticsTab(), "Diagnóstico");
      tabs->addTab(buildAdvancedTab(), "API avanzada");
    }
    root->addWidget(tabs, 1);

    if (expertMode_) {
      auto* outBox = new QGroupBox("Resultado", central);
      auto* outLayout = new QVBoxLayout(outBox);
      responseBox_ = new QPlainTextEdit(outBox);
      responseBox_->setReadOnly(true);
      outLayout->addWidget(responseBox_);
      root->addWidget(outBox, 1);

      auto* logBox = new QGroupBox("Log del backend", central);
      auto* logLayout = new QVBoxLayout(logBox);
      backendLogBox_ = new QPlainTextEdit(logBox);
      backendLogBox_->setReadOnly(true);
      logLayout->addWidget(backendLogBox_);
      root->addWidget(logBox, 1);
    }

    setCentralWidget(central);

    if (expertMode_) {
      connect(btnStart, &QPushButton::clicked, this, [this]() { startBackend(); });
      connect(btnStop, &QPushButton::clicked, this, [this]() { stopBackend(); });
      connect(btnHealth, &QPushButton::clicked, this, [this]() { quickHealth(); });
      connect(btnCerts, &QPushButton::clicked, this, [this]() { refreshCertificates(); });
    }
    if (presetCombo_) {
      connect(presetCombo_, &QComboBox::currentTextChanged, this, [this]() { applyPreset(); });
    }
  }

  QWidget* buildSignTab() {
    auto* tab = new QWidget(this);
    auto* grid = new QGridLayout(tab);

    signInputEdit_ = new QLineEdit(tab);
    signOutputEdit_ = new QLineEdit(tab);
    signFormatCombo_ = new QComboBox(tab);
    signActionCombo_ = new QComboBox(tab);
    signCertCombo_ = new QComboBox(tab);
    signReturnB64Check_ = new QCheckBox("Devolver firma en Base64", tab);

    signFormatCombo_->addItems({"pades", "cades", "xades", "facturae"});
    signActionCombo_->addItem("Firmar", "sign");
    signActionCombo_->addItem("Cofirmar", "cosign");
    signActionCombo_->addItem("Contrafirmar", "countersign");

    auto* btnBrowseIn = new QPushButton("Examinar entrada", tab);
    auto* btnBrowseOut = new QPushButton("Examinar salida", tab);
    auto* btnSign = new QPushButton("Firmar", tab);
    auto* btnSignRefreshCerts = new QPushButton("Actualizar certificados", tab);

    grid->addWidget(new QLabel("Fichero de entrada:"), 0, 0);
    grid->addWidget(signInputEdit_, 0, 1);
    grid->addWidget(btnBrowseIn, 0, 2);

    grid->addWidget(new QLabel("Fichero de salida (opcional):"), 1, 0);
    grid->addWidget(signOutputEdit_, 1, 1);
    grid->addWidget(btnBrowseOut, 1, 2);

    grid->addWidget(new QLabel("Formato:"), 2, 0);
    grid->addWidget(signFormatCombo_, 2, 1);

    grid->addWidget(new QLabel("Operacion:"), 3, 0);
    grid->addWidget(signActionCombo_, 3, 1);

    grid->addWidget(new QLabel("Certificado:"), 4, 0);
    grid->addWidget(signCertCombo_, 4, 1, 1, 2);

    grid->addWidget(signReturnB64Check_, 5, 0, 1, 2);
    grid->addWidget(btnSignRefreshCerts, 6, 1);
    grid->addWidget(btnSign, 6, 2);

    connect(btnBrowseIn, &QPushButton::clicked, this, [this]() {
      const QString p = QFileDialog::getOpenFileName(this, "Seleccionar documento", QString(),
                                                     "Documentos (*.pdf *.xml *.xsig *.csig *.txt *.bin);;Todos (*)");
      if (!p.isEmpty()) {
        signInputEdit_->setText(p);
        if (signOutputEdit_->text().trimmed().isEmpty()) {
          signOutputEdit_->setText(suggestSignedOutputPath(p));
        }
      }
    });
    connect(btnBrowseOut, &QPushButton::clicked, this, [this]() {
      const QString p = QFileDialog::getSaveFileName(this, "Guardar firmado", QString(), "Todos (*)");
      if (!p.isEmpty()) signOutputEdit_->setText(p);
    });
    connect(btnSignRefreshCerts, &QPushButton::clicked, this, [this]() { refreshCertificates(); });
    connect(btnSign, &QPushButton::clicked, this, [this]() { runSign(); });

    return tab;
  }

  QWidget* buildVerifyTab() {
    auto* tab = new QWidget(this);
    auto* grid = new QGridLayout(tab);

    verifyInputEdit_ = new QLineEdit(tab);
    verifySigEdit_ = new QLineEdit(tab);
    verifyOrigEdit_ = new QLineEdit(tab);
    verifyFormatCombo_ = new QComboBox(tab);
    verifyFormatCombo_->addItems({"auto", "pades", "cades", "xades", "facturae"});

    auto* btnBrowseIn = new QPushButton("Entrada", tab);
    auto* btnBrowseSig = new QPushButton("Firma", tab);
    auto* btnBrowseOrig = new QPushButton("Original", tab);
    auto* btnVerify = new QPushButton("Verificar", tab);

    grid->addWidget(new QLabel("Fichero firmado o firma:"), 0, 0);
    grid->addWidget(verifyInputEdit_, 0, 1);
    grid->addWidget(btnBrowseIn, 0, 2);

    grid->addWidget(new QLabel("Ruta de firma separada (opcional):"), 1, 0);
    grid->addWidget(verifySigEdit_, 1, 1);
    grid->addWidget(btnBrowseSig, 1, 2);

    grid->addWidget(new QLabel("Ruta original (opcional):"), 2, 0);
    grid->addWidget(verifyOrigEdit_, 2, 1);
    grid->addWidget(btnBrowseOrig, 2, 2);

    grid->addWidget(new QLabel("Formato:"), 3, 0);
    grid->addWidget(verifyFormatCombo_, 3, 1);
    grid->addWidget(btnVerify, 4, 2);

    connect(btnBrowseIn, &QPushButton::clicked, this, [this]() {
      const QString p = QFileDialog::getOpenFileName(this, "Seleccionar fichero", QString(), "Todos (*)");
      if (!p.isEmpty()) verifyInputEdit_->setText(p);
    });
    connect(btnBrowseSig, &QPushButton::clicked, this, [this]() {
      const QString p = QFileDialog::getOpenFileName(this, "Seleccionar firma", QString(), "Todos (*)");
      if (!p.isEmpty()) verifySigEdit_->setText(p);
    });
    connect(btnBrowseOrig, &QPushButton::clicked, this, [this]() {
      const QString p = QFileDialog::getOpenFileName(this, "Seleccionar original", QString(), "Todos (*)");
      if (!p.isEmpty()) verifyOrigEdit_->setText(p);
    });
    connect(btnVerify, &QPushButton::clicked, this, [this]() { runVerify(); });

    return tab;
  }

  QWidget* buildDiagnosticsTab() {
    auto* tab = new QWidget(this);
    auto* grid = new QGridLayout(tab);

    auto* btnHealth = new QPushButton("Salud", tab);
    auto* btnCerts = new QPushButton("Certificados", tab);
    auto* btnDiag = new QPushButton("Informe", tab);
    auto* btnTLSStatus = new QPushButton("Estado confianza TLS", tab);
    auto* btnTLSGen = new QPushButton("Generar certificados TLS", tab);
    auto* btnTLSInstall = new QPushButton("Instalar confianza TLS", tab);

    grid->addWidget(btnHealth, 0, 0);
    grid->addWidget(btnCerts, 0, 1);
    grid->addWidget(btnDiag, 0, 2);
    grid->addWidget(btnTLSStatus, 1, 0);
    grid->addWidget(btnTLSGen, 1, 1);
    grid->addWidget(btnTLSInstall, 1, 2);

    connect(btnHealth, &QPushButton::clicked, this, [this]() { quickHealth(); });
    connect(btnCerts, &QPushButton::clicked, this, [this]() { refreshCertificates(); });
    connect(btnDiag, &QPushButton::clicked, this, [this]() {
      callEndpoint("GET", "/diagnostics/report", QByteArray(), nullptr);
    });
    connect(btnTLSStatus, &QPushButton::clicked, this, [this]() {
      callEndpoint("GET", "/tls/trust-status", QByteArray(), nullptr);
    });
    connect(btnTLSGen, &QPushButton::clicked, this, [this]() {
      callEndpoint("POST", "/tls/generate-certs", QByteArray("{}"), nullptr);
    });
    connect(btnTLSInstall, &QPushButton::clicked, this, [this]() {
      callEndpoint("POST", "/tls/install-trust", QByteArray("{}"), nullptr);
    });

    return tab;
  }

  QWidget* buildAdvancedTab() {
    auto* tab = new QWidget(this);
    auto* reqLayout = new QGridLayout(tab);

    presetCombo_ = new QComboBox(tab);
    for (const auto& p : presets_) {
      presetCombo_->addItem(p.name);
    }
    methodCombo_ = new QComboBox(tab);
    methodCombo_->addItems({"GET", "POST", "DELETE"});
    pathEdit_ = new QLineEdit("/health", tab);
    bodyEdit_ = new QPlainTextEdit(tab);
    bodyEdit_->setPlaceholderText("{\"example\":true}");
    auto* btnSend = new QPushButton("Enviar petición", tab);

    reqLayout->addWidget(new QLabel("Preset"), 0, 0);
    reqLayout->addWidget(presetCombo_, 0, 1, 1, 3);
    reqLayout->addWidget(new QLabel("Método"), 1, 0);
    reqLayout->addWidget(methodCombo_, 1, 1);
    reqLayout->addWidget(new QLabel("Ruta"), 1, 2);
    reqLayout->addWidget(pathEdit_, 1, 3);
    reqLayout->addWidget(new QLabel("JSON body"), 2, 0, 1, 4);
    reqLayout->addWidget(bodyEdit_, 3, 0, 1, 4);
    reqLayout->addWidget(btnSend, 4, 3);

    connect(btnSend, &QPushButton::clicked, this, [this]() { sendRequest(); });
    applyPreset();
    return tab;
  }

  void initPresets() {
    presets_ = {
        {"GET /salud", "GET", "/health", ""},
        {"GET /certificados", "GET", "/certificates?check=1", ""},
        {"POST /firmar (PAdES)", "POST", "/sign", R"({"inputPath":"/ruta/documento.pdf","format":"pades","certificateIndex":0,"returnSignatureB64":false})"},
        {"POST /verificar", "POST", "/verify", R"({"inputPath":"/ruta/documento_firmado.pdf","format":"auto"})"},
        {"GET /diagnostico/informe", "GET", "/diagnostics/report", ""},
        {"GET /seguridad/dominios", "GET", "/security/domains", ""},
        {"POST /seguridad/dominios", "POST", "/security/domains", R"({"domain":"sede.ejemplo.gob.es"})"},
        {"DELETE /seguridad/dominios", "DELETE", "/security/domains", R"({"domain":"sede.ejemplo.gob.es"})"},
        {"GET /tls/estado-confianza", "GET", "/tls/trust-status", ""},
        {"POST /tls/generar-certificados", "POST", "/tls/generate-certs", "{}"},
        {"POST /tls/instalar-confianza", "POST", "/tls/install-trust", "{}"},
        {"POST /tls/limpiar-almacen", "POST", "/tls/clear-store", "{}"},
        {"GET /autenticacion/reto", "GET", "/auth/challenge", ""},
        {"POST /autenticacion/verificar", "POST", "/auth/verify", R"({"challengeId":"...","signatureB64":"...","certificatePEM":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"})"},
    };
  }

  QString baseURL() const {
    return QString("http://") + addrEdit_->text().trimmed();
  }

  void appendBackendLog(const QString& s) {
    if (!backendLogBox_) return;
    const QString t = s.trimmed();
    if (!t.isEmpty()) backendLogBox_->appendPlainText(t);
  }

  void setStatus(const QString& s) {
    if (statusLabel_) statusLabel_->setText(s);
  }

  void applyPreset() {
    if (!presetCombo_ || !methodCombo_ || !pathEdit_ || !bodyEdit_) return;
    const int idx = presetCombo_->currentIndex();
    if (idx < 0 || idx >= presets_.size()) return;
    const auto& p = presets_.at(idx);
    methodCombo_->setCurrentText(p.method);
    pathEdit_->setText(p.path);
    bodyEdit_->setPlainText(p.body);
  }

  void startBackend() {
    if (backend_ && backend_->state() != QProcess::NotRunning) {
      setStatus("Servicio ya iniciado");
      return;
    }
    stopBackend();

    const QString appDir = QCoreApplication::applicationDirPath();
    const QString desktopBin = findDesktopBinary(appDir);
    backend_ = new QProcess(this);
    backend_->setProgram(desktopBin);

    QStringList args;
    args << "--rest" << "--rest-addr" << addrEdit_->text().trimmed();
    if (!tokenEdit_->text().trimmed().isEmpty()) {
      args << "--rest-token" << tokenEdit_->text().trimmed();
    }
    backend_->setArguments(args);
    backend_->setProcessChannelMode(QProcess::SeparateChannels);

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    configureQtRuntimeEnv(env, appDir);
    backend_->setProcessEnvironment(env);

    QObject::connect(backend_, &QProcess::readyReadStandardOutput, this, [this]() {
      appendBackendLog(QString::fromUtf8(backend_->readAllStandardOutput()));
    });
    QObject::connect(backend_, &QProcess::readyReadStandardError, this, [this]() {
      appendBackendLog(QString::fromUtf8(backend_->readAllStandardError()));
    });
    QObject::connect(backend_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                     [this](int code, QProcess::ExitStatus) {
                       setStatus(QString("Servicio detenido (exit=%1)").arg(code));
                     });

    backend_->start();
    if (!backend_->waitForStarted(5000)) {
      appendBackendLog(QString("[QT_REAL] no se pudo iniciar backend: %1").arg(backend_->errorString()));
      setStatus("Error iniciando servicio");
      return;
    }
    setStatus("Servicio REST activo");
  }

  void stopBackend() {
    if (!backend_) return;
    if (backend_->state() == QProcess::NotRunning) {
      backend_->deleteLater();
      backend_ = nullptr;
      return;
    }
    backend_->terminate();
    if (!backend_->waitForFinished(3000)) {
      backend_->kill();
      backend_->waitForFinished(2000);
    }
    backend_->deleteLater();
    backend_ = nullptr;
    setStatus("Servicio detenido");
  }

  void quickHealth() {
    callEndpoint("GET", "/health", QByteArray(), nullptr);
  }

  void sendRequest() {
    const QString method = methodCombo_->currentText().trimmed().toUpper();
    const QString path = pathEdit_->text().trimmed();
    callEndpoint(method, path, bodyEdit_->toPlainText().toUtf8(), nullptr);
  }

  void callEndpoint(const QString& method,
                    const QString& path,
                    const QByteArray& body,
                    std::function<void(int, const QJsonDocument&)> onJSON) {
    const QString meth = method.trimmed().toUpper();
    QUrl url(baseURL() + path.trimmed());
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    const QString token = tokenEdit_->text().trimmed();
    if (!token.isEmpty()) {
      req.setRawHeader("Authorization", QString("Bearer %1").arg(token).toUtf8());
    }

    QNetworkReply* reply = nullptr;
    if (meth == "GET") {
      reply = nam_->get(req);
    } else if (meth == "POST") {
      reply = nam_->post(req, body);
    } else if (meth == "DELETE") {
      reply = nam_->sendCustomRequest(req, "DELETE", body);
    } else {
      if (responseBox_) {
        responseBox_->setPlainText("Método no soportado: " + meth);
      } else {
        QMessageBox::warning(this, "Error", "Método no soportado: " + meth);
      }
      return;
    }

    QObject::connect(reply, &QNetworkReply::finished, this, [this, reply, onJSON]() {
      const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
      const QByteArray raw = reply->readAll();
      const QString rawText = QString::fromUtf8(raw);

      QString out;
      out += QString("[%1] Código HTTP: %2\n").arg(QDateTime::currentDateTime().toString(Qt::ISODate), QString::number(status));
      const auto headers = reply->rawHeaderPairs();
      out += "Cabeceras:\n";
      for (const auto& h : headers) {
        out += QString::fromUtf8(h.first) + ": " + QString::fromUtf8(h.second) + "\n";
      }
      out += "\n";

      QJsonParseError jerr;
      const QJsonDocument doc = QJsonDocument::fromJson(raw, &jerr);
      if (jerr.error == QJsonParseError::NoError && !doc.isNull()) {
        out += "Cuerpo JSON (castellano):\n";
        out += QString::fromUtf8(localizeJSONDocument(doc).toJson(QJsonDocument::Indented));
        if (onJSON) onJSON(status, doc);
      } else {
        out += "Cuerpo:\n";
        out += QString::fromUtf8(raw);
      }

      if (responseBox_) {
        responseBox_->setPlainText(out);
      } else if (status >= 400) {
        const QString friendly = simplifyErrorMessage(rawText, out);
        QMessageBox::warning(this, "Error", friendly);
      }
      reply->deleteLater();
    });
  }

  void refreshCertificates() {
    callEndpoint("GET", "/certificates?check=1", QByteArray(), [this](int status, const QJsonDocument& doc) {
      if (status < 200 || status >= 300 || !doc.isObject()) return;

      const QJsonArray certs = doc.object().value("certificates").toArray();
      signCertCombo_->clear();
      for (const auto& item : certs) {
        const QJsonObject c = item.toObject();
        const int idx = c.value("index").toInt(-1);
        const QString id = c.value("id").toString();
        const QString name = c.value("name").toString();
        const bool canSign = c.value("canSign").toBool(false);
        const QString label = QString("[%1] %2%3").arg(QString::number(idx), name, canSign ? "" : " (no firma)");
        signCertCombo_->addItem(label, idx);
        signCertCombo_->setItemData(signCertCombo_->count() - 1, id, Qt::UserRole + 1);
      }
    });
  }

  void runSign() {
    const QString inputPath = signInputEdit_->text().trimmed();
    if (inputPath.isEmpty()) {
      QMessageBox::warning(this, "Falta entrada", "Debes seleccionar un fichero de entrada.");
      return;
    }

    QJsonObject body;
    body.insert("inputPath", inputPath);
    QString outputPath = signOutputEdit_->text().trimmed();
    if (outputPath.isEmpty()) {
      outputPath = suggestSignedOutputPath(inputPath);
      signOutputEdit_->setText(outputPath);
    }
    body.insert("outputPath", outputPath);
    body.insert("saveToDisk", true);
    body.insert("format", signFormatCombo_->currentText().trimmed().toLower());
    QString actionValue = signActionCombo_->currentData().toString().trimmed().toLower();
    if (actionValue.isEmpty()) actionValue = QStringLiteral("sign");
    body.insert("action", actionValue);
    body.insert("returnSignatureB64", signReturnB64Check_->isChecked());

    const int certIdx = signCertCombo_->currentData().toInt();
    if (certIdx >= 0) {
      body.insert("certificateIndex", certIdx);
    }

    callEndpoint("POST", "/sign", QJsonDocument(body).toJson(QJsonDocument::Compact),
                 [this, outputPath](int status, const QJsonDocument& doc) {
                   if (status < 200 || status >= 300 || !doc.isObject()) {
                     return;
                   }
                   QString signedPath = doc.object().value("outputPath").toString().trimmed();
                   if (signedPath.isEmpty()) {
                     signedPath = outputPath;
                   }
                   if (!signedPath.isEmpty()) {
                     lastSignedPath_ = signedPath;
                     verifyInputEdit_->setText(lastSignedPath_);
                   }
                   if (!expertMode_) {
                     QMessageBox::information(this, "Firma completada", "Documento firmado correctamente.");
                   }
                 });
  }

  void runVerify() {
    if (verifyInputEdit_->text().trimmed().isEmpty() && !lastSignedPath_.trimmed().isEmpty()) {
      verifyInputEdit_->setText(lastSignedPath_.trimmed());
    }
    const QString inputPath = verifyInputEdit_->text().trimmed();
    if (inputPath.isEmpty()) {
      QMessageBox::warning(this, "Falta entrada", "Debes seleccionar un fichero para verificar.");
      return;
    }

    QJsonObject body;
    body.insert("inputPath", inputPath);
    if (!verifySigEdit_->text().trimmed().isEmpty()) body.insert("signaturePath", verifySigEdit_->text().trimmed());
    if (!verifyOrigEdit_->text().trimmed().isEmpty()) body.insert("originalPath", verifyOrigEdit_->text().trimmed());
    body.insert("format", verifyFormatCombo_->currentText().trimmed().toLower());

    callEndpoint("POST", "/verify", QJsonDocument(body).toJson(QJsonDocument::Compact),
                 [this](int status, const QJsonDocument& doc) {
                   if (status < 200 || status >= 300 || !doc.isObject()) {
                     return;
                   }
                   const QJsonObject resultObj = doc.object().value("result").toObject();
                   const bool valid = resultObj.value("valid").toBool(false);
                   const QString reason = resultObj.value("reason").toString().trimmed();
                   if (!expertMode_) {
                     QMessageBox::information(this,
                                              "Verificación",
                                              valid ? "La firma es válida." : ("La firma no es válida.\n" + reason));
                   }
                 });
  }

  QString suggestSignedOutputPath(const QString& inputPath) const {
    const QFileInfo inInfo(inputPath);
    const QString dir = inInfo.dir().absolutePath();
    const QString base = inInfo.completeBaseName().trimmed().isEmpty() ? QStringLiteral("documento") : inInfo.completeBaseName().trimmed();
    QString ext = inInfo.suffix().trimmed().toLower();
    if (ext.isEmpty()) ext = QStringLiteral("pdf");
    return QDir(dir).filePath(base + QStringLiteral("_firmado.") + ext);
  }

  void relaunchWithMode(bool targetExpert) {
    QStringList args = QCoreApplication::arguments();
    if (!args.isEmpty()) {
      args.removeFirst();
    }

    QStringList filtered;
    for (const QString& a : args) {
      const QString l = a.trimmed().toLower();
      if (l == "--experto" || l == "-experto" || l == "--modo-experto" || l == "-modo-experto") {
        continue;
      }
      filtered << a;
    }
    if (targetExpert) {
      filtered << "--experto";
    }

    const QString program = QCoreApplication::applicationFilePath();
    const bool ok = QProcess::startDetached(program, filtered);
    if (!ok) {
      QMessageBox::warning(this, "Error", "No se pudo cambiar de modo.");
      return;
    }
    close();
  }

  QJsonDocument localizeJSONDocument(const QJsonDocument& doc) const {
    if (doc.isObject()) {
      return QJsonDocument(localizeJSONObject(doc.object()));
    }
    if (doc.isArray()) {
      return QJsonDocument(localizeJSONArray(doc.array()));
    }
    return doc;
  }

  QJsonObject localizeJSONObject(const QJsonObject& obj) const {
    QJsonObject out;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
      out.insert(translateKey(it.key()), localizeJSONValue(it.value()));
    }
    return out;
  }

  QJsonArray localizeJSONArray(const QJsonArray& arr) const {
    QJsonArray out;
    for (const auto& v : arr) {
      out.append(localizeJSONValue(v));
    }
    return out;
  }

  QJsonValue localizeJSONValue(const QJsonValue& v) const {
    if (v.isObject()) return QJsonValue(localizeJSONObject(v.toObject()));
    if (v.isArray()) return QJsonValue(localizeJSONArray(v.toArray()));
    return v;
  }

  QString translateKey(const QString& key) const {
    static const QMap<QString, QString> m = {
        {"ok", "ok"},
        {"error", "error"},
        {"service", "servicio"},
        {"version", "version"},
        {"timestamp", "fechaHora"},
        {"certificateCount", "numeroCertificados"},
        {"canSignCount", "numeroCertificadosFirmables"},
        {"trustedDomains", "dominiosConfiables"},
        {"endpointStoreDir", "directorioAlmacenEndpoints"},
        {"endpointStoreCount", "numeroEndpoints"},
        {"trustStatusLines", "lineasEstadoConfianza"},
        {"trustStatusError", "errorEstadoConfianza"},
        {"tokenEnabled", "tokenActivo"},
        {"certAuthEnabled", "autenticacionCertificadoActiva"},
        {"allowListCount", "numeroCertificadosPermitidos"},
        {"sessionTTLSeconds", "duracionSesionSegundos"},
        {"certificates", "certificados"},
        {"index", "indice"},
        {"id", "id"},
        {"name", "nombre"},
        {"nickname", "alias"},
        {"serialNumber", "numeroSerie"},
        {"validFrom", "validoDesde"},
        {"validTo", "validoHasta"},
        {"canSign", "puedeFirmar"},
        {"signIssue", "incidenciaFirma"},
        {"source", "origen"},
        {"format", "formato"},
        {"result", "resultado"},
        {"valid", "valida"},
        {"reason", "motivo"},
        {"outputPath", "rutaSalida"},
        {"renamed", "renombrado"},
        {"overwrote", "sobrescrito"},
        {"certificateId", "idCertificado"},
        {"signatureB64", "firmaB64"},
        {"action", "accion"},
        {"lines", "lineas"},
        {"removed", "eliminados"},
        {"domains", "dominios"},
    };
    return m.value(key, key);
  }

  QString simplifyErrorMessage(const QString& rawBody, const QString& fallback) const {
    const QString lower = rawBody.toLower();
    if (lower.contains("pin incorrect") || lower.contains("pin inválido") || lower.contains("pin invalido") ||
        lower.contains("wrong pin") || lower.contains("wrong password") || lower.contains("bad password") ||
        lower.contains("invalid password") || lower.contains("incorrect password") ||
        lower.contains("ckr_pin_incorrect") || lower.contains("ckr_pin_invalid") ||
        lower.contains("contraseña incorrecta") || lower.contains("contrasena incorrecta") ||
        lower.contains("clave incorrecta") || lower.contains("password is incorrect")) {
      return "La clave es incorrecta.";
    }
    if (lower.contains("certificat") && lower.contains("not found")) {
      return "No se encontró el certificado seleccionado.";
    }
    if (lower.contains("inputpath") || lower.contains("no such file") || lower.contains("fichero no existe")) {
      return "No se encontró el fichero indicado.";
    }
    return fallback;
  }
};

static bool shouldRunHeadlessDelegate(const QStringList& args) {
  for (const QString& a : args) {
    const QString t = a.trimmed();
    const QString l = t.toLower();
    if (l.startsWith("afirma://")) return true;
    if (l == "--version" || l == "-version") return true;
    if (l == "--rest" || l == "-rest" || l == "-servidor-rest") return true;
    if (l == "--server" || l == "-server") return true;
    if (l == "--cli" || l == "-cli" || l == "-modo-cli") return true;
    if (l == "--help" || l == "-help" || l == "-ayuda-detallada") return true;
  }
  return false;
}

static int runHeadlessDelegate(int argc, char* argv[]) {
  QCoreApplication app(argc, argv);
  const QString appDir = QCoreApplication::applicationDirPath();
  const QString desktopBin = findDesktopBinary(appDir);
  const QStringList args = sanitizeArgs(QCoreApplication::arguments().mid(1));

  QProcess p;
  p.setProgram(desktopBin);
  p.setArguments(args);
  p.setProcessChannelMode(QProcess::ForwardedChannels);
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  configureQtRuntimeEnv(env, appDir);
  p.setProcessEnvironment(env);
  p.start();
  if (!p.waitForStarted(5000)) {
    fprintf(stderr, "[QT_REAL] no se pudo iniciar backend: %s\n", qPrintable(p.errorString()));
    return 1;
  }
  if (!p.waitForFinished(-1)) {
    fprintf(stderr, "[QT_REAL] ejecución interrumpida: %s\n", qPrintable(p.errorString()));
    return 1;
  }
  return p.exitCode();
}

int main(int argc, char* argv[]) {
  QStringList rawArgs;
  for (int i = 1; i < argc; ++i) rawArgs << QString::fromLocal8Bit(argv[i]);
  if (shouldRunHeadlessDelegate(rawArgs)) {
    return runHeadlessDelegate(argc, argv);
  }

  if (qEnvironmentVariableIsEmpty("DBUS_SESSION_BUS_ADDRESS") && qEnvironmentVariableIsEmpty("GSETTINGS_BACKEND")) {
    qputenv("GSETTINGS_BACKEND", QByteArray("memory"));
  }

  bool expertMode = false;
  for (const QString& a : rawArgs) {
    const QString l = a.trimmed().toLower();
    if (l == "--experto" || l == "-experto" || l == "--modo-experto" || l == "-modo-experto") {
      expertMode = true;
      break;
    }
  }

  QApplication app(argc, argv);
  MainWindow w(expertMode);
  w.show();
  return app.exec();
}
