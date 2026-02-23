#include <QCoreApplication>
#include <QLocalSocket>
#include <QDebug>
#include <QFileInfo>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QLocalSocket s;
    s.connectToServer("/tmp/autofirma_ipc.sock");
    if (s.waitForConnected(500)) {
        qDebug() << "Connected!";
    } else {
        qDebug() << "Failed:" << s.errorString();
    }
    return 0;
}
