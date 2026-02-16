# Manual de Usuario: AutoFirma-Go

Bienvenido a **AutoFirma-Go**, la nueva versión de alta velocidad de la aplicación de firma electrónica. Esta guía le ayudará a instalar y utilizar la aplicación en su equipo.

## 1. ¿Qué es AutoFirma-Go?

Es una aplicación que permite firmar documentos electrónicamente en sitios web de la administración pública (Sede Electrónica, Hacienda, Seguridad Social, etc.) sin necesidad de utilizar Java.

**Ventajas:**
*   **Más rápida:** Se abre casi instantáneamente.
*   **Más ligera:** Consume muy pocos recursos de su ordenador.
*   **Sin Java:** No necesita instalar ni actualizar Java para funcionar.

---

## 2. Requisitos Previos

Antes de empezar, asegúrese de cumplir estos requisitos:

1.  **Certificado Digital:** Debe tener su certificado digital (FNMT, DNIe, etc.) ya instalado en su navegador o sistema operativo.
    *   **Windows:** El certificado debe aparecer en "Opciones de Internet" > "Contenido" > "Certificados".
    *   **Linux:** El certificado debe estar importado en su navegador (Firefox/Chrome) o configurado en el sistema.
2.  **Sistema Operativo:** Windows 10/11 o Linux (Ubuntu, Debian, Fedora, etc.).

---

## 3. Instalación

### En Linux (Recomendado)
1.  Descargue el instalador de última versión (`AutofirmaDipgra-linux-installer.run`).
2.  Abra una terminal y dé permisos de ejecución al archivo:
    ```bash
    chmod +x AutofirmaDipgra-linux-installer.run
    ```
3.  Ejecute el instalador (le pedirá la contraseña de administrador si es necesario):
    ```bash
    ./AutofirmaDipgra-linux-installer.run
    ```
4.  El instalador configurará automáticamente el protocolo `afirma://` y registrará el conector para sus navegadores instalados (Chrome, Firefox, Brave, Edge).
5.  Reinicie su navegador para completar la integración.

### En Windows
1.  Descargue el instalador `.exe` (ej: `AutofirmaDipgra-windows-installer.exe`).
2.  Ejecute el archivo descargado y siga las instrucciones del asistente.
3.  La aplicación se instalará y configurará el sistema automáticamente.

---

## 4. Uso de la Aplicación

AutoFirma-Go está diseñada para ser **invisible**. Usted no necesita abrirla manualmente para firmar.

### 4.1. Firma en Sitios Web Modernos
1.  Entre en la web donde necesita firmar el trámite.
2.  Pulse el botón de "Firmar" en la página web.
3.  Automáticamente aparecerá una ventana emergente del navegador pidiéndole que seleccione su certificado.
4.  Elija su certificado y pulse "Aceptar".
5.  El documento se firmará y el trámite continuará automáticamente.

### 4.2. Firma en Sitios Web Antiguos (Modo Compatibilidad)
Algunas webs antiguas utilizan un método de conexión diferente (WebSocket).
*   Si la web intenta conectar y no ocurre nada, asegúrese de que la aplicación `autofirma-desktop` esté ejecutándose.
*   Puede que necesite abrir manualmente la aplicación y dejarla en segundo plano si el sitio no la invoca automáticamente.

---

## 5. Solución de Problemas

### No aparecen mis certificados
*   Asegúrese de que su certificado no ha caducado.
*   Compruebe que el certificado está instalado en el almacén personal de su navegador.
*   Si usa una tarjeta criptográfica o DNIe, asegúrese de que el lector está conectado correctamente antes de intentar firmar.

### La web dice "No se ha podido conectar con AutoFirma"
1.  Cierre completamente su navegador y vuelva a abrirlo.
2.  Verifique que no haya un antivirus o firewall bloqueando el puerto `63117`.
3.  Pruebe a ejecutar manualmente la aplicación `autofirma-desktop` antes de entrar en la web.

### Herramienta de Diagnóstico
Si persiste el problema, puede usar la página de prueba incluida (`test-autofirma-wss.html`) para verificar la conexión con el servicio de firma.

---

**Soporte Técnico**
Si tiene problemas técnicos, contacte con el soporte de la oficina de administración electrónica correspondiente.
