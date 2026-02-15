# Prueba del Servidor WSS de AutoFirma

## 1. El servidor está corriendo

El servidor WSS (WebSocket Secure) está escuchando en `wss://127.0.0.1:63117/`

## 2. Cómo probar desde el navegador

### Paso 1: Aceptar el certificado autofirmado

1. Abre en el navegador: `https://127.0.0.1:63117/`
2. El navegador mostrará una advertencia de seguridad (certificado autofirmado)
3. Haz clic en "Avanzado" → "Aceptar el riesgo y continuar"
4. Esto permite que el navegador confíe en el certificado para conexiones WSS

### Paso 2: Probar la conexión WSS

Abre la consola del navegador (F12) en https://www.sededgsfp.gob.es/es/Paginas/TestAutofirma.aspx y ejecuta:

```javascript
// Conectar al servidor WSS
const ws = new WebSocket('wss://127.0.0.1:63117/');

ws.onopen = () => {
    console.log('✅ Conectado al servidor WSS de AutoFirma');
    // Enviar echo test
    ws.send('echo=test');
};

ws.onmessage = (event) => {
    console.log('📥 Respuesta:', event.data);
    if (event.data === 'OK') {
        console.log('✅ Echo test exitoso!');
        console.log('💡 El servidor WSS está funcionando correctamente');
    }
};

ws.onerror = (error) => {
    console.error('❌ Error:', error);
    console.log('💡 Asegúrate de haber aceptado el certificado en https://127.0.0.1:63117/');
};

ws.onclose = () => {
    console.log('🔌 Conexión cerrada');
};
```

### Paso 3: Probar firma completa

Una vez que el echo funcione, haz clic en "Firmar" en la página web. El navegador debería:
1. Conectarse automáticamente a `wss://127.0.0.1:63117/`
2. Enviar la petición `afirma://sign?...`
3. Recibir "OK" cuando la firma se complete
4. Mostrar éxito en la página

## 3. Verificar logs

```bash
# Ver logs del servidor
tail -f /tmp/autofirma-launcher.log

# Ver si el servidor está escuchando
lsof -i :63117
```

## 4. Solución de problemas

### Error: "WebSocket connection failed"
- Asegúrate de haber aceptado el certificado en `https://127.0.0.1:63117/`
- Verifica que el servidor esté corriendo: `lsof -i :63117`

### Error: "Certificate not trusted"
- Esto es normal con certificados autofirmados
- Debes aceptar el riesgo en el navegador

### El navegador sigue usando afirma:// en lugar de WSS
- La librería JavaScript de AutoFirma detecta automáticamente el servidor WSS
- Si no lo detecta, puede ser porque:
  - El certificado no está aceptado
  - El servidor no está corriendo
  - La versión de autoscript.js es antigua

## 5. Siguiente paso

Si el echo funciona pero la firma no, necesitamos investigar cómo la librería JavaScript de AutoFirma decide usar WSS vs protocolo handler.
