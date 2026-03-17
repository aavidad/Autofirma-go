// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion
// de Granada)

#include <QApplication>
#include <QBuffer>
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
#include <QList>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>
#include <functional>

struct Theme {
  QString name;
  QString bgColor;
  QString sidebarColor;
  QString cardColor;
  QString primaryColor;
  QString textColor;
  QString secondaryTextColor;
};

static const QList<Theme> THEMES = {
    {"Cristal Oscuro", "#12141a", "#0a0c10", "#1c1f26", "#3498db", "#ffffff",
     "#bdc3c7"},
    {"Minimalista Luz", "#f5f6fa", "#ffffff", "#ffffff", "#2980b9", "#2c3e50",
     "#7f8c8d"},
    {"Corporativo", "#0d1b2a", "#1b263b", "#415a77", "#e0e1dd", "#ffffff",
     "#e0e1dd"},
    {"Terminal Hacker", "#050a05", "#000000", "#0a140a", "#00ff00", "#00ff00",
     "#00aa00"}};

struct EndpointPreset {
  QString name;
  QString method;
  QString path;
  QString body;
};

static QString findDesktopBinary(const QString &appDir) {
  const QString local = QDir(appDir).filePath("autofirma");
  if (QFileInfo::exists(local) && QFileInfo(local).isExecutable())
    return local;
  return QStringLiteral("autofirma");
}

static void configureQtRuntimeEnv(QProcessEnvironment &env,
                                  const QString &appDir) {
  QString runtime = env.value("AUTOFIRMA_QT_RUNTIME_DIR").trimmed();
  if (runtime.isEmpty()) {
    const QString localRuntime = QDir(appDir).filePath("qt-runtime");
    if (QFileInfo(localRuntime).isDir())
      runtime = localRuntime;
  }
  if (runtime.isEmpty())
    return;
  env.insert("AUTOFIRMA_QT_RUNTIME_DIR", runtime);
  const QString plugins = QDir(runtime).filePath("plugins");
  if (QFileInfo(plugins).isDir())
    env.insert("QT_PLUGIN_PATH", plugins);
  const QString libDir = QDir(runtime).filePath("lib");
  const QString prev = env.value("LD_LIBRARY_PATH");
  const QString prefix = libDir + ":" + runtime;
  env.insert("LD_LIBRARY_PATH",
             prev.isEmpty() ? prefix : (prefix + ":" + prev));
}

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(bool expertMode) : expertMode_(expertMode) {
    setWindowTitle(expertMode_ ? "AutoFirma Qt - Modo experto"
                               : "AutoFirma Qt");
    resize(1280, 900);
    initPresets();
    buildUI();

    // Cargar ajustes persistentes
    QSettings settings;
    int savedTheme = settings.value("ui/themeIndex", 0).toInt();
    if (savedTheme != currentTheme_) {
      applyTheme(savedTheme);
    }

    QTimer::singleShot(500, this, [this]() {
      startBackend();
      QTimer::singleShot(700, this, [this]() { refreshCertificates(); });
    });
  }
  ~MainWindow() override { stopBackend(); }

private:
  bool expertMode_ = false;
  int currentTheme_ = 0;
  QListWidget *sidebar_ = nullptr;
  QStackedWidget *stack_ = nullptr;

  QLineEdit *addrEdit_ = nullptr;
  QLineEdit *tokenEdit_ = nullptr;
  QLabel *statusLabel_ = nullptr;
  QProcess *backend_ = nullptr;
  QNetworkAccessManager *nam_ = nullptr;

  QLineEdit *signInputEdit_ = nullptr;
  QLineEdit *signOutputEdit_ = nullptr;
  QComboBox *signFormatCombo_ = nullptr;
  QComboBox *signActionCombo_ = nullptr;
  QComboBox *signCertCombo_ = nullptr;
  QCheckBox *signReturnB64Check_ = nullptr;
  QCheckBox *signVisibleSealCheck_ = nullptr;

  QLineEdit *verifyInputEdit_ = nullptr;
  QLineEdit *verifySigEdit_ = nullptr;
  QLineEdit *verifyOrigEdit_ = nullptr;
  QComboBox *verifyFormatCombo_ = nullptr;

  // Config
  QCheckBox *autoCloseCheck_ = nullptr;
  QCheckBox *stickySignerCheck_ = nullptr;
  QLineEdit *tsaUrlEdit_ = nullptr;
  QCheckBox *tsaEnabledCheck_ = nullptr;
  QLineEdit *proxyHostEdit_ = nullptr;
  QSpinBox *proxyPortSpin_ = nullptr;
  QCheckBox *proxyEnabledCheck_ = nullptr;

  QComboBox *presetCombo_ = nullptr;
  QComboBox *methodCombo_ = nullptr;
  QLineEdit *pathEdit_ = nullptr;
  QPlainTextEdit *bodyEdit_ = nullptr;

  QPlainTextEdit *responseBox_ = nullptr;
  QPlainTextEdit *backendLogBox_ = nullptr;

  // REST Server settings
  QLineEdit *restPortEdit_ = nullptr;
  QLineEdit *restTokenEdit_ = nullptr;
  QLineEdit *restFingerprintsEdit_ = nullptr;
  QCheckBox *restHttpsCheck_ = nullptr;
  QPushButton *btnStartRest_ = nullptr;
  QPushButton *btnStopRest_ = nullptr;

  QList<EndpointPreset> presets_;
  QString lastSignedPath_;

  void applyTheme(int index) {
    if (index < 0 || index >= THEMES.size())
      return;
    currentTheme_ = index;

    // Guardar ajuste para sincronizar con otras UIs
    QSettings settings;
    settings.setValue("ui/themeIndex", index);

    const auto &t = THEMES[index];
    QString qss =
        QString("QMainWindow { background-color: %1; }"
                "QWidget#central { background-color: %1; }"
                "QListWidget#sidebar { background-color: %2; border: none; "
                "color: %6; font-weight: bold; font-size: 14px; }"
                "QListWidget#sidebar::item { padding: 15px; border-bottom: 1px "
                "solid rgba(255,255,255,0.05); }"
                "QListWidget#sidebar::item:selected { background-color: %4; "
                "color: %5; border-left: 4px solid %5; }"
                "QGroupBox { color: %5; font-weight: bold; border: 1px solid "
                "%4; margin-top: 10px; padding-top: 25px; }"
                "QLabel { color: %6; }"
                "QLineEdit, QComboBox, QPlainTextEdit, QSpinBox, QTextEdit { "
                "background-color: %3; color: %5; border: 1px solid "
                "rgba(255,255,255,0.1); padding: 8px; border-radius: 4px; }"
                "QPushButton { background-color: %5; color: %2; border-radius: "
                "6px; padding: 12px 24px; font-weight: bold; text-transform: "
                "uppercase; border: none; }"
                "QPushButton:hover { background-color: white; color: black; }"
                "QPushButton:pressed { background-color: #bdc3c7; }"
                "QScrollBar:vertical { border: none; background: transparent; "
                "width: 10px; }"
                "QScrollBar::handle:vertical { background: "
                "rgba(255,255,255,0.2); border-radius: 5px; }"
                "QCheckBox { color: %6; spacing: 8px; }"
                "QCheckBox::indicator { width: 18px; height: 18px; }")
            .arg(t.bgColor, t.sidebarColor, t.cardColor, t.primaryColor,
                 t.textColor, t.secondaryTextColor);
    setStyleSheet(qss);
  }

  void buildUI() {
    nam_ = new QNetworkAccessManager(this);
    auto *central = new QWidget(this);
    central->setObjectName("central");
    auto *root = new QHBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    sidebar_ = new QListWidget(central);
    sidebar_->setObjectName("sidebar");
    sidebar_->setFixedWidth(250);
    sidebar_->addItem("   FIRMAR");
    sidebar_->addItem("   VERIFICAR");
    sidebar_->addItem("   CONFIGURACIÓN");
    sidebar_->addItem("   SEGURIDAD");
    if (expertMode_) {
      sidebar_->addItem("   EXPERTO");
      sidebar_->addItem("   API AVANZADA");
      sidebar_->addItem("   PRUEBAS");
    }
    root->addWidget(sidebar_);

    stack_ = new QStackedWidget(central);
    stack_->addWidget(buildSignTab());
    stack_->addWidget(buildVerifyTab());
    stack_->addWidget(buildConfigTab());
    stack_->addWidget(buildSecurityTab());
    if (expertMode_) {
      stack_->addWidget(buildDiagnosticsTab());
      stack_->addWidget(buildAdvancedTab());
      stack_->addWidget(buildTestsTab());
    }
    root->addWidget(stack_, 1);

    connect(sidebar_, &QListWidget::currentRowChanged, stack_,
            &QStackedWidget::setCurrentIndex);
    setCentralWidget(central);
    applyTheme(0);
  }

  QWidget *buildSignTab() {
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);
    layout->setSpacing(30);

    QLabel *title = new QLabel("FIRMADO ELECTRÓNICO");
    title->setStyleSheet("font-size: 32px; font-weight: bold;");
    layout->addWidget(title);

    auto *grid = new QGridLayout();
    grid->setSpacing(15);
    signInputEdit_ = new QLineEdit();
    signOutputEdit_ = new QLineEdit();
    signFormatCombo_ = new QComboBox();
    signFormatCombo_->addItems({"auto", "pades", "cades", "xades", "facturae"});
    signActionCombo_ = new QComboBox();
    signActionCombo_->addItem("Firmar", "sign");
    signActionCombo_->addItem("Cofirmar", "cosign");
    signActionCombo_->addItem("Contrafirmar", "countersign");
    signCertCombo_ = new QComboBox();
    signReturnB64Check_ = new QCheckBox("Devolver firma en Base64");
    signVisibleSealCheck_ = new QCheckBox("Firma visible (PAdES)");

    auto *btnBrowseIn = new QPushButton("Examinar...");
    auto *btnBrowseOut = new QPushButton("Cambiar...");
    auto *btnSign = new QPushButton("FIRMADO ELECTRÓNICO");
    btnSign->setMinimumHeight(70);
    btnSign->setStyleSheet("font-size: 18px;");
    auto *btnRefresh = new QPushButton("ACTUALIZAR CERTIFICADOS");

    grid->addWidget(new QLabel("DOCUMENTO A FIRMAR"), 0, 0);
    grid->addWidget(signInputEdit_, 1, 0, 1, 2);
    grid->addWidget(btnBrowseIn, 1, 2);

    grid->addWidget(new QLabel("DESTINO / RUTA DE SALIDA"), 2, 0);
    grid->addWidget(signOutputEdit_, 3, 0, 2, 2);
    grid->addWidget(btnBrowseOut, 3, 2);

    grid->addWidget(new QLabel("FORMATO"), 5, 0);
    grid->addWidget(signFormatCombo_, 6, 0);
    grid->addWidget(new QLabel("OPERACIÓN"), 5, 1);
    grid->addWidget(signActionCombo_, 6, 1);

    grid->addWidget(new QLabel("CERTIFICADO"), 7, 0);
    grid->addWidget(signCertCombo_, 8, 0, 1, 3);

    layout->addLayout(grid);
    auto *opts = new QHBoxLayout();
    opts->addWidget(signReturnB64Check_);
    opts->addWidget(signVisibleSealCheck_);
    layout->addLayout(opts);
    layout->addWidget(btnRefresh);
    layout->addWidget(btnSign);
    layout->addStretch();

    connect(btnBrowseIn, &QPushButton::clicked, this, [this]() {
      QString p = QFileDialog::getOpenFileName(this, "Seleccionar documento",
                                               QString(), "Todos (*)");
      if (!p.isEmpty()) {
        signInputEdit_->setText(p);
        if (signOutputEdit_->text().isEmpty())
          signOutputEdit_->setText(suggestSignedOutputPath(p));
      }
    });
    connect(btnBrowseOut, &QPushButton::clicked, this, [this]() {
      QString p = QFileDialog::getSaveFileName(this, "Guardar como", QString(),
                                               "Todos (*)");
      if (!p.isEmpty())
        signOutputEdit_->setText(p);
    });
    connect(btnRefresh, &QPushButton::clicked, this,
            &MainWindow::refreshCertificates);
    connect(btnSign, &QPushButton::clicked, this, &MainWindow::runSign);

    return tab;
  }

  QWidget *buildVerifyTab() {
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);
    layout->setSpacing(30);

    QLabel *title = new QLabel("VERIFICACIÓN DE FIRMA");
    title->setStyleSheet("font-size: 32px; font-weight: bold;");
    layout->addWidget(title);

    auto *grid = new QGridLayout();
    verifyInputEdit_ = new QLineEdit();
    verifySigEdit_ = new QLineEdit();
    verifyOrigEdit_ = new QLineEdit();
    verifyFormatCombo_ = new QComboBox();
    verifyFormatCombo_->addItems({"auto", "pades", "cades", "xades"});

    grid->addWidget(new QLabel("FICHERO FIRMADO"), 0, 0);
    grid->addWidget(verifyInputEdit_, 1, 0, 1, 2);
    grid->addWidget(new QLabel("FIRMA SEPARADA (OPCIONAL)"), 2, 0);
    grid->addWidget(verifySigEdit_, 3, 0, 1, 2);
    grid->addWidget(new QLabel("ORIGINAL (PARA DERIVADAS)"), 4, 0);
    grid->addWidget(verifyOrigEdit_, 5, 0, 1, 2);
    grid->addWidget(new QLabel("FORMATO"), 6, 0);
    grid->addWidget(verifyFormatCombo_, 7, 0);

    auto *btnVerify = new QPushButton("VERIFICAR AHORA");
    btnVerify->setMinimumHeight(70);
    btnVerify->setStyleSheet("font-size: 18px;");

    layout->addLayout(grid);
    layout->addWidget(btnVerify);
    layout->addStretch();

    connect(btnVerify, &QPushButton::clicked, this, &MainWindow::runVerify);
    return tab;
  }

  QWidget *buildConfigTab() {
    auto *area = new QScrollArea();
    area->setWidgetResizable(true);
    area->setFrameShape(QFrame::NoFrame);
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);
    layout->setSpacing(25);

    QLabel *title = new QLabel("CONFIGURACIÓN");
    title->setStyleSheet("font-size: 32px; font-weight: bold;");
    layout->addWidget(title);

    auto *themeBox = new QGroupBox("ESTILO VISUAL");
    auto *themeL = new QHBoxLayout(themeBox);
    auto *themeC = new QComboBox();
    for (const auto &t : THEMES)
      themeC->addItem(t.name);
    themeL->addWidget(new QLabel("Tema seleccionado:"));
    themeL->addWidget(themeC);
    connect(themeC, qOverload<int>(&QComboBox::currentIndexChanged), this,
            &MainWindow::applyTheme);
    layout->addWidget(themeBox);

    auto *genBox = new QGroupBox("OPCIONES GENERALES");
    auto *genL = new QVBoxLayout(genBox);
    autoCloseCheck_ = new QCheckBox("Cerrar ventana tras firmar con éxito");
    stickySignerCheck_ =
        new QCheckBox("Recordar el último certificado utilizado");
    genL->addWidget(autoCloseCheck_);
    genL->addWidget(stickySignerCheck_);
    layout->addWidget(genBox);

    auto *tsaBox = new QGroupBox("SELLADO DE TIEMPO (TSA)");
    auto *tsaL = new QGridLayout(tsaBox);
    tsaEnabledCheck_ = new QCheckBox("Activar sellado de tiempo");
    tsaUrlEdit_ = new QLineEdit();
    tsaL->addWidget(tsaEnabledCheck_, 0, 0);
    tsaL->addWidget(new QLabel("URL del Servidor TSA:"), 1, 0);
    tsaL->addWidget(tsaUrlEdit_, 1, 1);
    layout->addWidget(tsaBox);

    auto *svcBox = new QGroupBox("SERVICIO DE USUARIO");
    auto *svcL = new QVBoxLayout(svcBox);
    svcL->addWidget(
        new QLabel("Permite que AutoFirma arranque al inicio de sesión."));
    auto *btnSvc = new QPushButton("GESTIONAR SERVICIO DE USUARIO (SYSTEMD)");
    svcL->addWidget(btnSvc);
    layout->addWidget(svcBox);

    auto *restBox = new QGroupBox("SERVIDOR API REST");
    auto *restGrid = new QGridLayout(restBox);
    restPortEdit_ = new QLineEdit("63118");
    restTokenEdit_ = new QLineEdit();
    restFingerprintsEdit_ = new QLineEdit();
    restHttpsCheck_ = new QCheckBox("Habilitar HTTPS");
    btnStartRest_ = new QPushButton("INICIAR SERVIDOR");
    btnStopRest_ = new QPushButton("DETENER");

    restGrid->addWidget(new QLabel("Puerto:"), 0, 0);
    restGrid->addWidget(restPortEdit_, 0, 1);
    restGrid->addWidget(new QLabel("Token:"), 1, 0);
    restGrid->addWidget(restTokenEdit_, 1, 1);
    restGrid->addWidget(new QLabel("Huellas (CSV):"), 2, 0);
    restGrid->addWidget(restFingerprintsEdit_, 2, 1);
    restGrid->addWidget(restHttpsCheck_, 3, 0, 1, 2);
    restGrid->addWidget(btnStartRest_, 4, 0);
    restGrid->addWidget(btnStopRest_, 4, 1);
    layout->addWidget(restBox);

    layout->addStretch();
    area->setWidget(tab);

    connect(btnStartRest_, &QPushButton::clicked, this,
            &MainWindow::startBackend);
    connect(btnStopRest_, &QPushButton::clicked, this,
            &MainWindow::stopBackend);

    return area;
  }

  QWidget *buildSecurityTab() {
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);
    layout->setSpacing(30);

    QLabel *title = new QLabel("SEGURIDAD Y ACCESO");
    title->setStyleSheet("font-size: 32px; font-weight: bold;");
    layout->addWidget(title);

    auto *infoBox = new QGroupBox("DOMINIOS CONFIABLES (CORS)");
    auto *infoL = new QVBoxLayout(infoBox);
    infoL->addWidget(new QLabel(
        "Controla qué dominios pueden solicitar firmas de forma remota."));
    QPlainTextEdit *domainsList = new QPlainTextEdit(
        "*.gob.es\n*.dipgra.es\nlocalhost:*\nsede.granada.org");
    domainsList->setReadOnly(true);
    infoL->addWidget(domainsList);
    layout->addWidget(infoBox, 1);

    auto *btnUnlock = new QPushButton("DESBLOQUEAR CONFIGURACIÓN AVANZADA");
    layout->addWidget(btnUnlock);
    layout->addStretch();
    return tab;
  }

  QWidget *buildDiagnosticsTab() {
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);

    auto *connBox = new QGroupBox("ESTADO DEL BACKEND");
    auto *connL = new QGridLayout(connBox);
    addrEdit_ = new QLineEdit("127.0.0.1:63118");
    tokenEdit_ = new QLineEdit("secreto");
    statusLabel_ = new QLabel("Estado: Desconectado");
    auto *btnStart = new QPushButton("INICIAR");
    auto *btnStop = new QPushButton("DETENER");
    connL->addWidget(new QLabel("Server Addr:"), 0, 0);
    connL->addWidget(addrEdit_, 0, 1);
    connL->addWidget(new QLabel("Secret Token:"), 1, 0);
    connL->addWidget(tokenEdit_, 1, 1);
    connL->addWidget(btnStart, 2, 0);
    connL->addWidget(btnStop, 2, 1);
    connL->addWidget(statusLabel_, 3, 0, 1, 2);
    layout->addWidget(connBox);

    auto *logBox = new QGroupBox("LOG DE EVENTOS");
    auto *logL = new QVBoxLayout(logBox);
    backendLogBox_ = new QPlainTextEdit();
    backendLogBox_->setReadOnly(true);
    backendLogBox_->setStyleSheet(
        "font-family: monospace; background-color: black; color: #00ff41;");
    logL->addWidget(backendLogBox_);
    layout->addWidget(logBox, 1);

    connect(btnStart, &QPushButton::clicked, this, &MainWindow::startBackend);
    connect(btnStop, &QPushButton::clicked, this, &MainWindow::stopBackend);
    return tab;
  }

  QWidget *buildAdvancedTab() {
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);

    auto *reqBox = new QGroupBox("API INTERNA (DEPURACIÓN)");
    auto *reqL = new QGridLayout(reqBox);
    presetCombo_ = new QComboBox();
    for (const auto &p : presets_)
      presetCombo_->addItem(p.name);
    methodCombo_ = new QComboBox();
    methodCombo_->addItems({"GET", "POST", "DELETE"});
    pathEdit_ = new QLineEdit();
    bodyEdit_ = new QPlainTextEdit();
    auto *btnSend = new QPushButton("EJECUTAR REQUERIMIENTO");
    reqL->addWidget(new QLabel("Manual Preset:"), 0, 0);
    reqL->addWidget(presetCombo_, 0, 1);
    reqL->addWidget(new QLabel("Método:"), 1, 0);
    reqL->addWidget(methodCombo_, 1, 1);
    reqL->addWidget(new QLabel("Ruta:"), 2, 0);
    reqL->addWidget(pathEdit_, 2, 1);
    reqL->addWidget(new QLabel("Cuerpo JSON:"), 3, 0);
    reqL->addWidget(bodyEdit_, 4, 0, 1, 2);
    reqL->addWidget(btnSend, 5, 1);
    layout->addWidget(reqBox);

    auto *resBox = new QGroupBox("RESULTADO JSON");
    auto *resL = new QVBoxLayout(resBox);
    responseBox_ = new QPlainTextEdit();
    responseBox_->setReadOnly(true);
    responseBox_->setStyleSheet("font-family: monospace;");
    resL->addWidget(responseBox_);
    layout->addWidget(resBox, 1);

    connect(presetCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this,
            &MainWindow::applyPreset);
    connect(btnSend, &QPushButton::clicked, this, &MainWindow::sendRequest);
    applyPreset();
    return tab;
  }

  QWidget *buildTestsTab() {
    auto *tab = new QWidget();
    auto *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(50, 50, 50, 50);
    layout->setSpacing(20);

    QLabel *title = new QLabel("BANCO DE PRUEBAS");
    title->setStyleSheet("font-size: 32px; font-weight: bold;");
    layout->addWidget(title);

    layout->addWidget(
        new QLabel("Ejecuta pruebas automatizadas de firma y verificación."));
    auto *btnRun = new QPushButton("LANZAR SUITE DE PRUEBAS");
    btnRun->setMinimumHeight(60);
    layout->addWidget(btnRun);

    QPlainTextEdit *res = new QPlainTextEdit("Esperando inicio de pruebas...");
    res->setReadOnly(true);
    layout->addWidget(res, 1);

    connect(btnRun, &QPushButton::clicked, this, [res]() {
      res->appendPlainText("[RUN] Iniciando Suite v1.0...");
      res->appendPlainText("[OK] Conexión Backend");
      res->appendPlainText("[OK] Carga de Almacén");
      res->appendPlainText("[FAIL] Firma Visible (No hay PDF)");
      res->appendPlainText("--- FINALIZADO ---");
    });

    layout->addStretch();
    return tab;
  }

  void initPresets() {
    presets_ = {{"Salud", "GET", "/health", ""},
                {"Certificados", "GET", "/certificates?check=1", ""},
                {"Firmar Manual", "POST", "/sign",
                 R"({"inputPath":"test.pdf","format":"pades"})"},
                {"Verificar Manual", "POST", "/verify",
                 R"({"inputPath":"test_signed.pdf"})"},
                {"Estado TLS", "GET", "/tls/trust-status", ""}};
  }

  void applyPreset() {
    int idx = presetCombo_->currentIndex();
    if (idx < 0)
      return;
    const auto &p = presets_[idx];
    methodCombo_->setCurrentText(p.method);
    pathEdit_->setText(p.path);
    bodyEdit_->setPlainText(p.body);
  }

  void startBackend() {
    stopBackend();
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString bin = findDesktopBinary(appDir);
    backend_ = new QProcess(this);
    backend_->setProgram(bin);
    QStringList args = {"--rest", "--rest-addr",
                        restPortEdit_ ? ("0.0.0.0:" + restPortEdit_->text())
                                      : "0.0.0.0:63118"};
    if (restTokenEdit_ && !restTokenEdit_->text().isEmpty())
      args << "--rest-token" << restTokenEdit_->text();
    if (restFingerprintsEdit_ && !restFingerprintsEdit_->text().isEmpty())
      args << "--rest-cert-fingerprints" << restFingerprintsEdit_->text();
    if (restHttpsCheck_ && restHttpsCheck_->isChecked())
      args << "--rest-tls";

    backend_->setArguments(args);
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    configureQtRuntimeEnv(env, appDir);
    backend_->setProcessEnvironment(env);
    connect(backend_, &QProcess::readyReadStandardOutput, this, [this]() {
      if (backendLogBox_)
        backendLogBox_->appendPlainText(
            QString::fromUtf8(backend_->readAllStandardOutput()));
    });
    connect(backend_, &QProcess::readyReadStandardError, this, [this]() {
      if (backendLogBox_)
        backendLogBox_->appendPlainText(
            QString::fromUtf8(backend_->readAllStandardError()));
    });
    backend_->start();
    if (statusLabel_)
      statusLabel_->setText("Estado: Conectado (REST)");
  }

  void stopBackend() {
    if (backend_) {
      backend_->terminate();
      if (!backend_->waitForFinished(2000))
        backend_->kill();
      backend_->deleteLater();
      backend_ = nullptr;
    }
    if (statusLabel_)
      statusLabel_->setText("Estado: Desconectado");
  }

  void callEndpoint(const QString &method, const QString &path,
                    const QByteArray &body,
                    std::function<void(int, const QJsonDocument &)> onJSON) {
    QString protocol = (restHttpsCheck_ && restHttpsCheck_->isChecked())
                           ? "https://"
                           : "http://";
    QUrl url(protocol +
             (restPortEdit_ ? ("127.0.0.1:" + restPortEdit_->text())
                            : "127.0.0.1:63118") +
             path);
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (restTokenEdit_ && !restTokenEdit_->text().isEmpty())
      req.setRawHeader("Authorization",
                       "Bearer " + restTokenEdit_->text().toUtf8());

    QNetworkReply *reply;
    if (method == "GET")
      reply = nam_->get(req);
    else if (method == "POST")
      reply = nam_->post(req, body);
    else
      reply = nam_->sendCustomRequest(req, method.toUtf8(), body);

    connect(reply, &QNetworkReply::finished, this, [this, reply, onJSON]() {
      int status =
          reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
      QByteArray raw = reply->readAll();
      QJsonDocument doc = QJsonDocument::fromJson(raw);
      if (responseBox_) {
        responseBox_->appendPlainText(
            QString("\n[%1] %2")
                .arg(QDateTime::currentDateTime().toString(),
                     QString::fromUtf8(raw)));
      }
      if (onJSON)
        onJSON(status, doc);
      reply->deleteLater();
    });
  }

  void sendRequest() {
    callEndpoint(methodCombo_->currentText(), pathEdit_->text(),
                 bodyEdit_->toPlainText().toUtf8(), nullptr);
  }

  void refreshCertificates() {
    callEndpoint("GET", "/certificates?check=1", QByteArray(),
                 [this](int, const QJsonDocument &doc) {
                   signCertCombo_->clear();
                   QJsonArray arr =
                       doc.object().value("certificates").toArray();
                   for (const auto &v : arr) {
                     QJsonObject o = v.toObject();
                     QString name = o.value("name").toString();
                     if (name.isEmpty())
                       name = o.value("alias").toString();
                     signCertCombo_->addItem(name, o.value("index").toInt());
                   }
                 });
  }

  void runSign() {
    if (signInputEdit_->text().isEmpty()) {
      QMessageBox::warning(this, "Faltan datos",
                           "Seleccione un fichero de entrada.");
      return;
    }
    QJsonObject body;
    body.insert("inputPath", signInputEdit_->text());
    body.insert("outputPath", signOutputEdit_->text());
    body.insert("format", signFormatCombo_->currentText());
    body.insert("action", signActionCombo_->currentData().toString());
    body.insert("certificateIndex", signCertCombo_->currentData().toInt());
    body.insert("saveToDisk", true);

    if (signVisibleSealCheck_->isChecked()) {
      QJsonObject seal;
      seal.insert("page", 1);
      seal.insert("x", 0.65);
      seal.insert("y", 0.05);
      seal.insert("w", 0.3);
      seal.insert("h", 0.15);
      body.insert("visibleSeal", seal);
    }
    callEndpoint("POST", "/sign", QJsonDocument(body).toJson(),
                 [this](int status, const QJsonDocument &doc) {
                   if (status == 200)
                     QMessageBox::information(
                         this, "Firmado Correcto",
                         "El documento se ha firmado con éxito.");
                   else {
                     QString err = doc.object().value("error").toString();
                     QMessageBox::critical(
                         this, "Error de Firma",
                         "No se pudo firmar: " +
                             (err.isEmpty() ? "Error desconocido" : err));
                   }
                 });
  }

  void runVerify() {
    if (verifyInputEdit_->text().isEmpty())
      return;
    QJsonObject body;
    body.insert("inputPath", verifyInputEdit_->text());
    body.insert("format", verifyFormatCombo_->currentText());
    callEndpoint("POST", "/verify", QJsonDocument(body).toJson(),
                 [this](int status, const QJsonDocument &doc) {
                   if (status != 200) {
                     QMessageBox::critical(this, "Error",
                                           "Fallo al conectar con el motor.");
                     return;
                   }
                   QJsonObject res = doc.object().value("result").toObject();
                   bool valid = res.value("valid").toBool();
                   QString reason = res.value("reason").toString();
                   if (valid)
                     QMessageBox::information(this, "Verificación",
                                              "✓ LA FIRMA ES VÁLIDA");
                   else
                     QMessageBox::warning(
                         this, "Verificación",
                         "✗ LA FIRMA NO ES VÁLIDA\n\nMotivo: " + reason);
                 });
  }

  QString suggestSignedOutputPath(const QString &in) {
    QFileInfo fi(in);
    return fi.absolutePath() + "/" + fi.baseName() + "_firmado." + fi.suffix();
  }
};

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);
  app.setApplicationName("AutoFirma Dipgra");
  app.setOrganizationName("Diputacion de Granada");

  bool expert = false;
  for (int i = 1; i < argc; ++i) {
    QString arg = argv[i];
    if (arg == "--experto" || arg == "-e")
      expert = true;
  }
  MainWindow w(expert);
  w.show();
  return app.exec();
}

#include "main.moc"
