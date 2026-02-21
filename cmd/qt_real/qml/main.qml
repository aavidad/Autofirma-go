import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

Window {
    id: window
    visible: true
    width: 1200
    height: 850
    title: "AutoFirma Dipgra"
    color: currentTheme.backgroundColor

    // --- TEMAS ---
    property int currentThemeIndex: 0
    property var themes: [
        {
            name: "Cristal Oscuro",
            backgroundColor: "#12141a",
            sidebarColor: "#0a0c10",
            cardColor: "#1c1f26",
            primaryColor: "#3498db",
            accentColor: "#2ecc71",
            textColor: "#ffffff",
            secondaryTextColor: "#bdc3c7",
            borderOpacity: 0.1
        },
        {
            name: "Minimalista Luz",
            backgroundColor: "#f5f6fa",
            sidebarColor: "#ffffff",
            cardColor: "#ffffff",
            primaryColor: "#2980b9",
            accentColor: "#e74c3c",
            textColor: "#2c3e50",
            secondaryTextColor: "#7f8c8d",
            borderOpacity: 0.2
        },
        {
            name: "Futurista",
            backgroundColor: "#050505",
            sidebarColor: "#000000",
            cardColor: "#0d0d0d",
            primaryColor: "#00f2ff",
            accentColor: "#bc00ff",
            textColor: "#ffffff",
            secondaryTextColor: "#00f2ff",
            borderOpacity: 0.3
        },
        {
            name: "Corporativo",
            backgroundColor: "#0d1b2a",
            sidebarColor: "#1b263b",
            cardColor: "#415a77",
            primaryColor: "#e0e1dd",
            accentColor: "#778da9",
            textColor: "#ffffff",
            secondaryTextColor: "#e0e1dd",
            borderOpacity: 0.1
        }
    ]

    property var currentTheme: themes[currentThemeIndex]
    property string activeTab: "firmar"
    property var certificates: []
    property int selectedCertIndex: -1
    property string currentFilePath: ""
    property string statusMessage: "Iniciando..."

    // --- DIALOGOS ---
    FileDialog {
        id: fileDialog
        title: "Seleccionar documento PDF"
        nameFilters: ["Archivos PDF (*.pdf)"]
        onAccepted: {
            let path = selectedFile.toString()
            if (path.startsWith("file://")) path = path.substring(7)
            window.currentFilePath = path
        }
    }

    // --- LOGICA DE BACKEND ---
    Connections {
        target: backend
        function onCertificatesLoaded(certs) {
            console.log("QML: Certificados recibidos:", certs.length)
            window.certificates = certs
            if (certs.length > 0 && selectedCertIndex === -1) {
                selectedCertIndex = 0
            }
        }
        function onStatusChanged() {
            window.statusMessage = backend.status
        }
        function onSigningFinished(success, message, outPath) {
            window.statusMessage = message
            if (success) {
                // Éxito
            }
        }
        function onVerificationFinished(success, message, details) {
            window.statusMessage = message
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // SIDEBAR
        Rectangle {
            Layout.fillHeight: true
            width: 350
            color: currentTheme.sidebarColor

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 30
                spacing: 40

                // Logo Container - Maximized
                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 300
                    Image {
                        source: "../assets/Logo-Horizontal-Color.svg"
                        anchors.fill: parent
                        fillMode: Image.PreserveAspectFit
                        anchors.margins: 15
                    }
                }

                // Navegación
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 15
                    
                    NavButton { 
                        text: "FIRMAR"
                        iconTxt: "✍"
                        active: activeTab === "firmar"
                        onClicked: activeTab = "firmar"
                    }
                    NavButton { 
                        text: "VERIFICAR"
                        iconTxt: "✓"
                        active: activeTab === "verificar"
                        onClicked: activeTab = "verificar"
                    }
                    NavButton { 
                        text: "CONFIGURACIÓN"
                        iconTxt: "⚙"
                        active: activeTab === "config"
                        onClicked: activeTab = "config"
                    }
                    NavButton { 
                        text: "EXPERTO"
                        iconTxt: "☣"
                        active: activeTab === "experto"
                        visible: backend.expertMode
                        onClicked: activeTab = "experto"
                    }
                }

                Item { Layout.fillHeight: true }

                // Selector de Temas
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 5
                    Text {
                        text: "TEMA VISUAL"
                        color: currentTheme.secondaryTextColor
                        font.pixelSize: 10
                        font.bold: true
                    }
                    ComboBox {
                        Layout.fillWidth: true
                        model: ["Cristal Oscuro", "Minimalista Luz", "Futurista", "Corporativo"]
                        currentIndex: window.currentThemeIndex
                        onActivated: window.currentThemeIndex = index
                    }
                }
            }
        }

        // --- CONTENIDO ---
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: activeTab === "firmar" ? 0 : (activeTab === "verificar" ? 1 : (activeTab === "config" ? 2 : 3))

            // TAB: FIRMAR
            Item {
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 40
                    spacing: 40

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 20

                        Text {
                            text: "Firma Digital"
                            font.pixelSize: 32
                            font.bold: true
                            color: currentTheme.textColor
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 400
                            radius: 15
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor
                            border.width: dropArea.containsDrag ? 3 : 1
                            
                            DropArea {
                                id: dropArea
                                anchors.fill: parent
                                property bool containsDrag: false
                                onEntered: containsDrag = true
                                onExited: containsDrag = false
                                onDropped: (drop) => {
                                    containsDrag = false
                                    if (drop.hasUrls) {
                                        let path = drop.urls[0].toString()
                                        if (path.startsWith("file://")) path = path.substring(7)
                                        window.currentFilePath = path
                                    }
                                }
                            }

                            ColumnLayout {
                                anchors.centerIn: parent
                                spacing: 15
                                Text {
                                    text: window.currentFilePath === "" ? "Arrastra o selecciona un PDF" : window.currentFilePath.split('/').pop()
                                    color: currentTheme.textColor
                                    font.pixelSize: 18
                                    Layout.alignment: Qt.AlignCenter
                                }
                                Button {
                                    text: "Seleccionar Archivo"
                                    Layout.alignment: Qt.AlignCenter
                                    onClicked: fileDialog.open()
                                }
                            }
                        }

                        RowLayout {
                             spacing: 15
                             Layout.fillWidth: true
                             ColumnLayout {
                                 Text { text: "Operación"; color: "white"; font.pixelSize: 12 }
                                 Item {
                                     width: 150; height: 40
                                     Rectangle { anchors.fill: parent; color: currentTheme.cardColor; radius: 5; border.color: currentTheme.primaryColor }
                                     Text { anchors.centerIn: parent; text: "Firmar PAdES"; color: "white" } // Placeholder for actual ComboBox
                                 }
                             }
                             ColumnLayout {
                                 Layout.fillWidth: true
                                 CheckBox {
                                     id: visibleSealChk
                                     text: "Firma visible"
                                     palette.windowText: "white"
                                 }
                             }
                         }

                        RowLayout {
                            spacing: 10
                            Button {
                                text: "Firmar ahora"
                                font.bold: true
                                palette.button: currentTheme.primaryColor
                                palette.buttonText: "white"
                                enabled: window.currentFilePath !== "" && selectedCertIndex !== -1
                                onClicked: backend.signFile(window.currentFilePath, "", selectedCertIndex, "pades")
                            }
                            Button {
                                text: "Limpiar"
                                onClicked: window.currentFilePath = ""
                            }
                        }
                    }

                    // Panel certificados
                    Rectangle {
                        Layout.fillHeight: true
                        width: 320
                        radius: 15
                        color: currentTheme.sidebarColor
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 20
                            spacing: 15
                            
                            RowLayout {
                                Layout.fillWidth: true
                                Text { 
                                    text: "CERTIFICADOS"; 
                                    color: currentTheme.textColor; 
                                    font.bold: true; 
                                    Layout.fillWidth: true 
                                }
                                Button {
                                    text: "Importar"
                                    flat: true
                                    onClicked: backend.openCertManager()
                                }
                                Button {
                                    text: "Actualizar"
                                    flat: true
                                    onClicked: backend.refreshCertificates()
                                }
                            }

                            ListView {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                model: window.certificates
                                spacing: 8
                                clip: true
                                delegate: Rectangle {
                                    width: ListView.view.width
                                    height: 70
                                    radius: 12
                                    color: selectedCertIndex === index ? currentTheme.primaryColor : currentTheme.cardColor
                                    border.color: "white"
                                    border.width: selectedCertIndex === index ? 2 : 0
                                    
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 12
                                        spacing: 2
                                        RowLayout {
                                            Layout.fillWidth: true
                                            Text {
                                                text: modelData.subjectName || "Certificado"
                                                color: "white"
                                                font.bold: true
                                                Layout.fillWidth: true
                                                elide: Text.ElideRight
                                            }
                                            Text {
                                                text: modelData.status || ""
                                                color: modelData.canSign ? "#2ecc71" : "#e74c3c"
                                                font.pixelSize: 10
                                                font.bold: true
                                            }
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            Text {
                                                text: "Vence: " + (modelData.validTo || "Desconocida")
                                                color: "white"
                                                opacity: 0.7
                                                font.pixelSize: 10
                                                Layout.fillWidth: true
                                            }
                                            Text {
                                                text: modelData.issuerName || ""
                                                color: "white"
                                                opacity: 0.5
                                                font.pixelSize: 9
                                                elide: Text.ElideRight
                                            }
                                        }
                                    }
                                    MouseArea { anchors.fill: parent; onClicked: selectedCertIndex = index }
                                }
                            }
                        }
                    }
                }
            }

            // TAB: VERIFICAR
            Item {
                id: verifyTab
                property string verifyFilePath: ""
                property var verifyDetails: null

                Connections {
                    target: backend
                    function onVerificationFinished(success, message, details) {
                        if (activeTab === "verificar") {
                            verifyTab.verifyDetails = details
                        }
                    }
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 40
                    spacing: 40

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 20

                        Text {
                            text: "Verificación de Firma"
                            font.pixelSize: 32
                            font.bold: true
                            color: currentTheme.textColor
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 300
                            radius: 15
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor
                            border.width: verifyDrop.containsDrag ? 3 : 1
                            
                            DropArea {
                                id: verifyDrop
                                anchors.fill: parent
                                property bool containsDrag: false
                                onEntered: containsDrag = true
                                onExited: containsDrag = false
                                onDropped: (drop) => {
                                    containsDrag = false
                                    if (drop.hasUrls) {
                                        let path = drop.urls[0].toString()
                                        if (path.startsWith("file://")) path = path.substring(7)
                                        verifyTab.verifyFilePath = path
                                    }
                                }
                            }

                            ColumnLayout {
                                anchors.centerIn: parent
                                spacing: 15
                                Text {
                                    text: verifyTab.verifyFilePath === "" ? "Arrastra un archivo firmado para verificar" : verifyTab.verifyFilePath.split('/').pop()
                                    color: currentTheme.textColor
                                    font.pixelSize: 18
                                    Layout.alignment: Qt.AlignCenter
                                }
                                Button {
                                    text: "Validar Documento"
                                    enabled: verifyTab.verifyFilePath !== ""
                                    onClicked: backend.verifyFile(verifyTab.verifyFilePath)
                                }
                            }
                        }

                        // Resultado Detallado
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            radius: 15
                            color: currentTheme.sidebarColor
                            visible: verifyTab.verifyDetails !== null
                            
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 20
                                spacing: 10
                                Text {
                                    text: "DETALLES DE LA FIRMA"
                                    font.bold: true
                                    color: currentTheme.primaryColor
                                }
                                ScrollView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    ColumnLayout {
                                        width: parent.width
                                        Text { 
                                            text: "Estado: " + (verifyTab.verifyDetails && verifyTab.verifyDetails.Valid ? "✅ VÁLIDA" : "❌ NO VÁLIDA")
                                            color: "white"; font.pixelSize: 16 
                                        }
                                        Text { 
                                            text: "Firmante: " + (verifyTab.verifyDetails ? verifyTab.verifyDetails.SignerName : "")
                                            color: "white"; visible: verifyTab.verifyDetails && verifyTab.verifyDetails.SignerName
                                        }
                                        Text { 
                                            text: "Email: " + (verifyTab.verifyDetails ? verifyTab.verifyDetails.SignerEmail : "")
                                            color: "white"; visible: verifyTab.verifyDetails && verifyTab.verifyDetails.SignerEmail
                                        }
                                        Text { 
                                            text: "Fecha: " + (verifyTab.verifyDetails ? verifyTab.verifyDetails.Timestamp : "")
                                            color: "white"; visible: verifyTab.verifyDetails && verifyTab.verifyDetails.Timestamp
                                        }
                                        Text { 
                                            text: "Razón: " + (verifyTab.verifyDetails ? verifyTab.verifyDetails.Reason : "")
                                            color: "#e74c3c"; visible: verifyTab.verifyDetails && !verifyTab.verifyDetails.Valid
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Item {
                id: configTab

                // Service status polled from backend
                property bool svcInstalled: false
                property bool svcRunning: false
                property string svcPlatform: ""
                property string svcMethod: ""
                property string svcMessage: ""

                function refreshServiceStatus() {
                    backend.getServiceStatus()
                }

                Connections {
                    target: backend
                    function onServiceStatusReceived(installed, running, platform, method) {
                        configTab.svcInstalled = installed
                        configTab.svcRunning   = running
                        configTab.svcPlatform  = platform
                        configTab.svcMethod    = method
                    }
                    function onServiceActionFinished(ok, message) {
                        configTab.svcMessage = message
                        configTab.refreshServiceStatus()
                    }
                }

                // Poll status when tab becomes active
                Connections {
                    target: window
                    function onActiveTabChanged() {
                        if (window.activeTab === "config") configTab.refreshServiceStatus()
                    }
                }

                ScrollView {
                    anchors.fill: parent
                    contentWidth: parent.width

                    ColumnLayout {
                        width: parent.width
                        anchors.margins: 40
                        spacing: 25

                        Text {
                            text: "Configuración"
                            font.pixelSize: 32; font.bold: true
                            color: currentTheme.textColor
                        }

                        // ── Modo experto ─────────────────────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            height: 70
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1

                            RowLayout {
                                anchors.fill: parent; anchors.margins: 20; spacing: 15
                                Text { text: "⚡  Modo Experto"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 15; Layout.fillWidth: true }
                                Switch {
                                    id: expertSwitch
                                    text: "Activar"
                                    checked: backend.expertMode
                                    onToggled: backend.expertMode = expertSwitch.checked
                                }
                            }
                        }

                        // ── Servicio del sistema ──────────────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1
                            height: svcColumn.implicitHeight + 40

                            ColumnLayout {
                                id: svcColumn
                                anchors { top: parent.top; left: parent.left; right: parent.right; margins: 20 }
                                spacing: 16

                                Text {
                                    text: "🔧  Servicio de Usuario al Inicio de Sesión"
                                    color: currentTheme.textColor; font.bold: true; font.pixelSize: 15
                                }

                                Text {
                                    text: "Instala el motor de firma como servicio de tu usuario (no de sistema),\npara que arranque automáticamente y tenga acceso a tus certificados personales."
                                    color: currentTheme.secondaryTextColor; font.pixelSize: 12
                                    wrapMode: Text.Wrap; Layout.fillWidth: true
                                }

                                // Estado actual
                                Rectangle {
                                    Layout.fillWidth: true; height: 44; radius: 8
                                    color: configTab.svcRunning ? "#1a4a1a" : (configTab.svcInstalled ? "#4a3a0a" : "#2a0a0a")
                                    border.color: configTab.svcRunning ? "#2ecc71" : (configTab.svcInstalled ? "#f39c12" : "#e74c3c")
                                    border.width: 1

                                    RowLayout {
                                        anchors.fill: parent; anchors.margins: 12; spacing: 10
                                        Text {
                                            text: configTab.svcRunning ? "● Servicio activo y corriendo" :
                                                  configTab.svcInstalled ? "● Servicio instalado pero parado" : "● Servicio no instalado"
                                            color: configTab.svcRunning ? "#2ecc71" : (configTab.svcInstalled ? "#f39c12" : "#e74c3c")
                                            font.bold: true; font.pixelSize: 13; Layout.fillWidth: true
                                        }
                                        Text {
                                            text: configTab.svcMethod ? "(" + configTab.svcMethod + ")" : ""
                                            color: currentTheme.secondaryTextColor; font.pixelSize: 11
                                        }
                                    }
                                }

                                // Botones de acción
                                Flow {
                                    Layout.fillWidth: true; spacing: 10

                                    Button {
                                        text: "Instalar servicio"
                                        visible: !configTab.svcInstalled
                                        palette.button: currentTheme.primaryColor; palette.buttonText: "white"
                                        onClicked: backend.installService()
                                    }
                                    Button {
                                        text: "Desinstalar servicio"
                                        visible: configTab.svcInstalled
                                        palette.button: "#c0392b"; palette.buttonText: "white"
                                        onClicked: backend.uninstallService()
                                    }
                                    Button {
                                        text: "Iniciar ahora"
                                        visible: configTab.svcInstalled && !configTab.svcRunning
                                        palette.button: "#27ae60"; palette.buttonText: "white"
                                        onClicked: backend.startService()
                                    }
                                    Button {
                                        text: "Detener"
                                        visible: configTab.svcInstalled && configTab.svcRunning
                                        palette.button: "#e67e22"; palette.buttonText: "white"
                                        onClicked: backend.stopService()
                                    }
                                    Button {
                                        text: "↻ Actualizar estado"
                                        flat: true
                                        onClicked: configTab.refreshServiceStatus()
                                    }
                                }

                                // Mensaje de resultado
                                Text {
                                    text: configTab.svcMessage
                                    color: configTab.svcMessage.startsWith("Error") ? "#e74c3c" : "#2ecc71"
                                    font.pixelSize: 12; wrapMode: Text.Wrap
                                    Layout.fillWidth: true
                                    visible: configTab.svcMessage !== ""
                                }

                                // Nota importante
                                Rectangle {
                                    Layout.fillWidth: true; height: noteText.implicitHeight + 20
                                    radius: 8; color: "#1a1a0a"
                                    border.color: "#f39c12"; border.width: 1

                                    Text {
                                        id: noteText
                                        anchors { fill: parent; margins: 10 }
                                        text: "⚠ Importante: se instala como servicio de tu sesión de usuario (no como servicio de sistema), para que tenga acceso a tus certificados del almacén personal. Los servicios de sistema no pueden acceder a los certificados del usuario."
                                        color: "#f39c12"; font.pixelSize: 11; wrapMode: Text.Wrap
                                    }
                                }
                            }
                        }

                        Item { height: 20 } // spacer
                    }
                }
            }
            Item {
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 30
                    spacing: 20
                    
                    RowLayout {
                        Layout.fillWidth: true
                        ColumnLayout {
                            Layout.fillWidth: true
                            Text { text: "Panel de Diagnóstico Experto"; font.pixelSize: 28; font.bold: true; color: currentTheme.textColor }
                            Text { text: "Gestión avanzada y resolución de problemas"; color: currentTheme.secondaryTextColor }
                        }
                        Button {
                            text: "Reiniciar Backend"
                            onClicked: {
                                backend.stopBackend()
                                if (isIpcMode) {
                                    backend.startBackend("/tmp/autofirma_ipc.sock")
                                } else {
                                    backend.startBackend("127.0.0.1:63118", "secreto")
                                }
                            }
                        }
                    }

                    // Botonera Experta
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 15
                        
                        Text { text: "SOPORTE Y DOCUMENTACIÓN"; color: currentTheme.primaryColor; font.bold: true; font.pixelSize: 12 }
                        Flow {
                            Layout.fillWidth: true; spacing: 10
                            Button { text: "Gestor Certificados"; onClicked: backend.openCertManager() }
                            Button { text: "Explorar Logs"; onClicked: backend.openLogFolder() }
                            Button { text: "Abrir Ayuda"; onClicked: backend.openHelpManual() }
                            Button { text: "Copiar Diag."; onClicked: backend.exportDiagnosticReport() }
                        }
                        
                        Text { text: "RED Y SEGURIDAD"; color: currentTheme.primaryColor; font.bold: true; font.pixelSize: 12 }
                        Flow {
                            Layout.fillWidth: true; spacing: 10
                            Button { text: "Diag. TLS"; onClicked: backend.runTLSDiagnostics() }
                            Button { text: "Vaciar Almacén TLS"; onClicked: backend.clearTLSTrustStore() }
                            Button { text: "Whitelist Dominios"; onClicked: activeTab = "seguridad" } // Placeholder
                        }

                        Text { text: "SISTEMA"; color: currentTheme.primaryColor; font.bold: true; font.pixelSize: 12 }
                        Flow {
                            Layout.fillWidth: true; spacing: 10
                            Button { text: "Comprobar Certs"; onClicked: backend.checkCertificates() }
                            Button { text: "Pruebas de Integración"; onClicked: activeTab = "pruebas" } // Placeholder
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        color: "#050505"
                        radius: 8
                        border.color: currentTheme.primaryColor
                        border.width: 1
                        
                        ScrollView {
                            anchors.fill: parent
                            clip: true
                            TextArea {
                                id: logArea
                                readOnly: true
                                color: "#00ff41"
                                font.family: "Monospace"
                                font.pixelSize: 12
                                wrapMode: TextEdit.Wrap
                                text: "--- INICIO DE LOGS ---\n"
                                
                                Connections {
                                    target: backend
                                    function onBackendLogReceived(log) {
                                        logArea.append("[" + new Date().toLocaleTimeString() + "] " + log)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // --- COMPONENTES ---
    component NavButton : Rectangle {
        id: navButtonRoot
        property string text: ""
        property string iconTxt: ""
        property bool active: false
        signal clicked()

        Layout.fillWidth: true
        height: 45
        radius: 8
        color: active ? currentTheme.primaryColor : "transparent"
        border.color: active ? "white" : "transparent"
        border.width: active ? 1 : 0

        MouseArea {
            anchors.fill: parent
            onClicked: navButtonRoot.clicked()
            hoverEnabled: true
            onEntered: if(!navButtonRoot.active) navButtonRoot.opacity = 0.7
            onExited: navButtonRoot.opacity = 1.0
        }

        RowLayout {
            anchors.fill: parent
            anchors.margins: 10
            Text { text: iconTxt; color: "white"; font.bold: true; Layout.preferredWidth: 20 }
            Text { text: navButtonRoot.text; color: "white"; font.bold: active; Layout.fillWidth: true }
        }
    }

    // Status Bar - Dynamic
    Rectangle {
        anchors.bottom: parent.bottom
        width: parent.width
        height: 30
        color: statusMessage.startsWith("Error") ? "#c0392b" : currentTheme.sidebarColor
        opacity: 0.95
        
        RowLayout {
            anchors.centerIn: parent
            spacing: 10
            Text {
                text: statusMessage.startsWith("Error") ? "⚠" : "ℹ"
                color: "white"
                font.bold: true
                visible: statusMessage !== ""
            }
            Text {
                text: window.statusMessage
                color: "white"
                font.pixelSize: 12
                font.bold: statusMessage.startsWith("Error")
            }
        }
        
        Behavior on color { ColorAnimation { duration: 300 } }
    }
}
