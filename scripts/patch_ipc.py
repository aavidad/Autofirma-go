import sys

path = "cmd/qt_real/ipcbridge.cpp"
with open(path) as f:
    content = f.read()

old = '''void IpcBridge::startBackend(const QString &socketPath) {
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
}'''

new = '''void IpcBridge::startBackend(const QString &socketPath) {
  m_socketPath = socketPath;

  if (m_socket->state() == QLocalSocket::ConnectedState)
    return;

  // Comprobar si el socket esta vivo
  bool needsLaunch = true;
  if (QFileInfo::exists(socketPath)) {
    QLocalSocket testSocket;
    testSocket.connectToServer(socketPath);
    if (testSocket.waitForConnected(500)) {
      testSocket.disconnectFromServer();
      needsLaunch = false;
      emit backendLogReceived("Socket activo encontrado. Conectando...");
    } else {
      emit backendLogReceived("Socket muerto encontrado. Limpiando y arrancando...");
      QFile::remove(socketPath);
    }
  } else {
    emit backendLogReceived("Socket no encontrado. Arrancando backend Go...");
  }

  if (needsLaunch) {
    launchBackendProcess();
  }

  // Ahora si conectamos el socket definitivo
  tryConnect();
}'''

if old in content:
    content = content.replace(old, new)
    with open(path, 'w') as f: f.write(content)
    print("Patched startBackend")
else:
    print("Not found startBackend")
