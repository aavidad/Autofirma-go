#ifndef IPCBRIDGE_H
#define IPCBRIDGE_H

#include <QLocalSocket>
#include <QObject>
#include <QProcess>
#include <QString>
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

  Q_INVOKABLE void startBackend(const QString &socketPath);
  Q_INVOKABLE void stopBackend();
  Q_INVOKABLE void refreshCertificates();
  Q_INVOKABLE void signFile(const QString &inputPath, const QString &outputPath,
                            int certIndex, const QString &format);
  Q_INVOKABLE void verifyFile(const QString &inputPath);
  Q_INVOKABLE void openCertManager();
  Q_INVOKABLE void openLogFolder();
  Q_INVOKABLE void openHelpManual();
  Q_INVOKABLE void checkCertificates();
  Q_INVOKABLE void runTLSDiagnostics();
  Q_INVOKABLE void exportDiagnosticReport();
  Q_INVOKABLE void clearTLSTrustStore();

  bool expertMode() const { return m_expertMode; }
  void setExpertMode(bool v);

signals:
  void certificatesLoaded(QVariantList certs);
  void signingFinished(bool success, QString message, QString outputPath);
  void verificationFinished(bool success, QString message, QVariantMap details);
  void backendLogReceived(QString log);
  void expertModeChanged();
  void statusChanged();

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
  QProcess *m_process = nullptr;
  QString m_status = "Iniciando IPC...";
  bool m_expertMode = false;
  QString m_socketPath;
  int m_retryCount = 0;
};

#endif // IPCBRIDGE_H
