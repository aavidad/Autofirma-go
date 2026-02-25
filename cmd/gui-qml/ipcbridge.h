#ifndef IPCBRIDGE_H
#define IPCBRIDGE_H

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

class IpcBridge : public QObject {
  Q_OBJECT
  Q_PROPERTY(bool expertMode READ expertMode WRITE setExpertMode NOTIFY
                 expertModeChanged)
  Q_PROPERTY(QString status READ status NOTIFY statusChanged)

public:
  explicit IpcBridge(QObject *parent = nullptr);
  ~IpcBridge();

  QString status() const { return m_status; }

  Q_INVOKABLE void startBackend(const QString &addr, const QString &token = "",
                                const QString &mode = "ipc",
                                const QString &fingerprints = "",
                                bool useTLS = false);
  Q_INVOKABLE void stopBackend();
  Q_INVOKABLE void refreshCertificates();
  Q_INVOKABLE void signFile(const QString &inputPath, const QString &outputPath,
                            int certIndex, const QString &format);
  Q_INVOKABLE void signFileAdvanced(const QString &inputPath,
                                    const QString &outputPath, int certIndex,
                                    const QVariantMap &options);
  Q_INVOKABLE void verifyFile(const QString &inputPath);
  Q_INVOKABLE void updateStatus(const QString &msg) { setStatus(msg); }
  Q_INVOKABLE void openExternal(const QString &path);
  Q_INVOKABLE void openCertManager();
  Q_INVOKABLE void openLogFolder();
  Q_INVOKABLE void openHelpManual();
  Q_INVOKABLE void checkCertificates();
  Q_INVOKABLE void runTLSDiagnostics();
  Q_INVOKABLE void exportDiagnosticReport();
  Q_INVOKABLE void clearTLSTrustStore();
  // Service management (via IPC)
  Q_INVOKABLE void getServiceStatus();
  Q_INVOKABLE void installService();
  Q_INVOKABLE void uninstallService();
  Q_INVOKABLE void startService();
  Q_INVOKABLE void stopService();
  Q_INVOKABLE void getSettings();
  Q_INVOKABLE void saveSettings(const QVariantMap &settings);
  Q_INVOKABLE void getPdfPreview(const QString &path, int page = 1);
  Q_INVOKABLE void importCertificate(const QString &path,
                                     const QString &password);
  Q_INVOKABLE void installPublicRoots();

  bool expertMode() const { return m_expertMode; }
  void setExpertMode(bool v);

signals:
  void certificatesLoaded(QVariantList certs);
  void signingFinished(bool success, QString message, QString outputPath);
  void verificationFinished(bool success, QString message, QVariantMap details);
  void backendLogReceived(QString log);
  void expertModeChanged();
  void statusChanged();
  void serviceStatusReceived(bool installed, bool running, QString platform,
                             QString method);
  void serviceActionFinished(bool ok, QString message);
  void settingsLoaded(QVariantMap settings);
  void pdfPreviewReceived(bool ok, QString data, double width, double height);
  void certificateImportFinished(bool ok, QString message);
  void publicRootsInstallationFinished(bool ok, QString message);

private slots:
  void onReadyRead();
  void onConnected();
  void onError(QLocalSocket::LocalSocketError error);

private:
  void sendRequest(const QString &action,
                   const QVariantMap &params = QVariantMap());
  void launchBackendProcess();
  void tryConnect();
  void setStatus(const QString &s) {
    m_status = s;
    emit statusChanged();
  }

  QLocalSocket *m_socket;
  QNetworkAccessManager *m_nam = nullptr;
  QProcess *m_process = nullptr;
  QString m_status = "Iniciando IPC...";
  bool m_expertMode = false;
  QString m_addr;
  QString m_token;
  QString m_socketPath; // For socket connection
  QString m_serverMode = "ipc";
  QString m_fingerprints;
  bool m_useTLS = false;
  int m_retryCount = 0;
  QString m_pendingAction; // ultima accion enviada, para distinguir respuestas
};

#endif // IPCBRIDGE_H
