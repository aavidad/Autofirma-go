#ifndef BACKENDBRIDGE_H
#define BACKENDBRIDGE_H

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QVariantList>
#include <QVariantMap>

class BackendBridge : public QObject {
  Q_OBJECT
  Q_PROPERTY(QString status READ status NOTIFY statusChanged)
  Q_PROPERTY(bool expertMode READ expertMode WRITE setExpertMode NOTIFY
                 expertModeChanged)

public:
  explicit BackendBridge(QObject *parent = nullptr);
  ~BackendBridge();

  QString status() const { return m_status; }
  bool expertMode() const { return m_expertMode; }
  void setExpertMode(bool v);

  Q_INVOKABLE void startBackend(const QString &addr, const QString &token);
  Q_INVOKABLE void stopBackend();
  Q_INVOKABLE void signFile(const QString &inputPath, const QString &outputPath,
                            int certIndex, const QString &format);
  Q_INVOKABLE void refreshCertificates();
  Q_INVOKABLE void verifyFile(const QString &inputPath);
  Q_INVOKABLE void updateStatus(const QString &msg) { setStatus(msg); }
  Q_INVOKABLE void openCertManager();
  Q_INVOKABLE void openLogFolder();
  Q_INVOKABLE void openHelpManual();
  Q_INVOKABLE void checkCertificates();
  Q_INVOKABLE void runTLSDiagnostics();
  Q_INVOKABLE void exportDiagnosticReport();
  Q_INVOKABLE void clearTLSTrustStore();
  // Service management
  Q_INVOKABLE void getServiceStatus();
  Q_INVOKABLE void installService();
  Q_INVOKABLE void uninstallService();
  Q_INVOKABLE void startService();
  Q_INVOKABLE void stopService();

signals:
  void statusChanged();
  void expertModeChanged();
  void certificatesLoaded(QVariantList certs);
  void signingFinished(bool success, QString message, QString outputPath);
  void verificationFinished(bool success, QString message, QVariantMap details);
  void backendLogReceived(QString log);
  void serviceStatusReceived(bool installed, bool running, QString platform,
                             QString method);
  void serviceActionFinished(bool ok, QString message);

private slots:
  void onBackendReadyRead();
  void onNetworkReplyFinished(QNetworkReply *reply);

private:
  QString m_status = "Iniciada";
  bool m_expertMode = false;
  QProcess *m_process = nullptr;
  QNetworkAccessManager *m_nam = nullptr;
  QString m_addr = "127.0.0.1:63118";
  QString m_token;

  void setStatus(const QString &s);
};

#endif // BACKENDBRIDGE_H
