# AutoFirma WebSocket Server - Usage Guide

Licencia: GPLv3.
Autor: Alberto Avidad Fernandez.
Organizacion: Oficina de Software Libre de la Diputacion de Granada.

## Starting the WebSocket Server

```bash
cd /home/alberto/Trabajo/GrxGo/plugin_autofirma_native/native-host
./dist/autofirma-desktop --server
```

The server will start on `localhost:63117` and wait for WebSocket connections from the browser.

## Testing the WebSocket Server

### 1. Test Echo (Health Check)

Open browser console on any page and run:

```javascript
const ws = new WebSocket('ws://localhost:63117');

ws.onopen = () => {
    console.log('Connected to AutoFirma');
    ws.send('echo=test');
};

ws.onmessage = (event) => {
    console.log('Response:', event.data); // Should print "OK"
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};
```

### 2. Test Full Signing Flow

From the AutoFirma test page (https://www.sededgsfp.gob.es/es/Paginas/TestAutofirma.aspx):

1. Make sure the WebSocket server is running (`./dist/autofirma-desktop --server`)
2. Click "Firmar" button on the web page
3. The browser will connect to `ws://localhost:63117`
4. Send the `afirma://sign?...` request
5. Server will process, sign, and upload
6. Server will respond with "OK"
7. Browser will show success

## Logs

All activity is logged to `/tmp/autofirma-launcher.log`:

```bash
tail -f /tmp/autofirma-launcher.log
```

## Modes

### WebSocket Server Mode (for browser integration)
```bash
./dist/autofirma-desktop --server
```
- Runs persistently
- Listens on port 63117
- Handles multiple signing requests
- Auto-selects first available certificate

### Direct Protocol Handler Mode (for desktop integration)
```bash
./dist/autofirma-desktop "afirma://sign?fileid=xxx&rtservlet=..."
```
- Launches once per request
- Shows UI for certificate selection
- Exits after completion

## Troubleshooting

### Port Already in Use
```bash
# Check if port 63117 is in use
lsof -i :63117

# Kill existing process
pkill -9 autofirma
```

### WebSocket Connection Refused
- Make sure server is running with `--server` flag
- Check logs: `tail /tmp/autofirma-launcher.log`
- Verify no firewall blocking localhost:63117

### Certificate Not Found
- Run `certutil -d sql:$HOME/.pki/nssdb -L` to list certificates
- Make sure at least one certificate is installed
- Check logs for certificate loading errors

## Next Steps

1. **Auto-start on boot**: Create systemd service
2. **Certificate selection UI**: Add dialog for WebSocket mode
3. **Error handling**: Improve error messages sent to browser
4. **Session management**: Handle multiple browser tabs
