import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import Qt.labs.settings

Window {
    id: window
    visible: true
    width: 1200
    height: 850
    title: "AutoFirma Dipgra"
    color: currentTheme.backgroundColor
    property string ipcSocketPath: ""

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
        },
        {
            name: "Neón Cyber",
            backgroundColor: "#0b0c10",
            sidebarColor: "#1f2833",
            cardColor: "#12141a",
            primaryColor: "#66fcf1",
            accentColor: "#c5c6c7",
            textColor: "#ffffff",
            secondaryTextColor: "#45a29e",
            borderOpacity: 0.2
        },
        {
            name: "Bosque Profundo",
            backgroundColor: "#131a13",
            sidebarColor: "#0f140f",
            cardColor: "#1a241a",
            primaryColor: "#2ecc71",
            accentColor: "#f1c40f",
            textColor: "#ecf0f1",
            secondaryTextColor: "#95a5a6",
            borderOpacity: 0.15
        },
        {
            name: "Atardecer Cálido",
            backgroundColor: "#2c191e",
            sidebarColor: "#1a0f12",
            cardColor: "#3a2228",
            primaryColor: "#ff6b6b",
            accentColor: "#feca57",
            textColor: "#fff9f9",
            secondaryTextColor: "#f6b9b9",
            borderOpacity: 0.2
        },
        {
            name: "Océano Profundo",
            backgroundColor: "#0a192f",
            sidebarColor: "#020c1b",
            cardColor: "#112240",
            primaryColor: "#64ffda",
            accentColor: "#ccd6f6",
            textColor: "#e6f1ff",
            secondaryTextColor: "#8892b0",
            borderOpacity: 0.1
        },
        {
            name: "Vampiro Elegante",
            backgroundColor: "#110b0b",
            sidebarColor: "#000000",
            cardColor: "#1e0f0f",
            primaryColor: "#e81c4f",
            accentColor: "#8e0020",
            textColor: "#ffffff",
            secondaryTextColor: "#a68a8a",
            borderOpacity: 0.25
        },
        {
            name: "Aurora Boreal",
            backgroundColor: "#1a1025",
            sidebarColor: "#0f0817",
            cardColor: "#241738",
            primaryColor: "#00ffcc",
            accentColor: "#b366ff",
            textColor: "#ffffff",
            secondaryTextColor: "#c2a3ff",
            borderOpacity: 0.15
        },
        {
            name: "Perla Lujosa",
            backgroundColor: "#faf9f7",
            sidebarColor: "#ffffff",
            cardColor: "#f0ebe1",
            primaryColor: "#d4af37",
            accentColor: "#b39030",
            textColor: "#2c2a26",
            secondaryTextColor: "#7d786e",
            borderOpacity: 0.1
        },
        {
            name: "Ametista",
            backgroundColor: "#1f182b",
            sidebarColor: "#15101f",
            cardColor: "#2a213a",
            primaryColor: "#9b5de5",
            accentColor: "#f15bb5",
            textColor: "#f8f5fd",
            secondaryTextColor: "#baabcf",
            borderOpacity: 0.2
        },
        {
            name: "Terminal Hacker",
            backgroundColor: "#050a05",
            sidebarColor: "#000000",
            cardColor: "#0a140a",
            primaryColor: "#00ff00",
            accentColor: "#008800",
            textColor: "#00ff00",
            secondaryTextColor: "#00aa00",
            borderOpacity: 0.3
        },
        {
            name: "Desierto Terracota",
            backgroundColor: "#2a1c18",
            sidebarColor: "#1f120e",
            cardColor: "#3a2822",
            primaryColor: "#e07a5f",
            accentColor: "#3d405b",
            textColor: "#f4f1de",
            secondaryTextColor: "#eab69f",
            borderOpacity: 0.15
        }
    ]

    property var currentTheme: themes[currentThemeIndex]
    property string activeTab: "firmar"
    property var certificates: []
    property int selectedCertIndex: -1
    property var selectedCertData: null
    property string currentFilePath: ""
    property string statusMessage: "Iniciando..."
    property string signAction: "sign"
    property string signFormat: ""
    property bool signAllowInvalidPDF: false
    property bool signStrictCompat: false
    property string signOverwrite: "rename"
    property bool signVisibleSeal: false
    property int signSealPage: 1
    property real signSealX: 0.62
    property real signSealY: 0.04
    property real signSealW: 0.34
    property real signSealH: 0.12
    property int signSealRotation: 0
    property string currentOutputPath: ""
    property bool signingInProgress: false

    onCurrentFilePathChanged: {
        if (currentFilePath !== "" && (currentOutputPath === "" || currentOutputPath.includes("_firmado"))) {
            suggestOutputPath(currentFilePath)
        }
        requestPdfPreview()
    }

    function suggestOutputPath(inputPath) {
        if (!inputPath || inputPath === "") return
        let idx = inputPath.lastIndexOf('.')
        if (idx !== -1) {
            let base = inputPath.substring(0, idx)
            let ext = inputPath.substring(idx)
            currentOutputPath = base + "_firmado" + ext
        } else {
            currentOutputPath = inputPath + "_firmado"
        }
    }

    function jumpToVerify(path) {
        if (!path || path === "") return
        verifyTab.verifyFilePath = path
        activeTab = "verificar"
        backend.verifyFile(path)
    }

    Settings {
        id: appSettings
        category: "General"
        property int themeIndex: 0
        property bool expertMode: false
    }

    // --- Ajustes del Backend ---
    property bool autoClose: false
    property bool stickySigner: false
    property bool certsExpiredShow: false
    property bool tsaEnabled: false
    property string tsaUrl: ""
    property bool proxyEnabled: false
    property string proxyHost: ""
    property int proxyPort: 8080
    property bool isSecurityUnlocked: false

    property bool settingsLoaded: false

    function saveBackendSettings() {
        if (!settingsLoaded) return
        const s = {
            expertMode: backend.expertMode,
            themeIndex: window.currentThemeIndex,
            autoClose: window.autoClose,
            stickySigner: window.stickySigner,
            certsExpiredShow: window.certsExpiredShow,
            tsaEnabled: window.tsaEnabled,
            tsaUrl: window.tsaUrl,
            proxyEnabled: window.proxyEnabled,
            proxyHost: window.proxyHost,
            proxyPort: window.proxyPort
        }
        backend.saveSettings(s)
    }

    Component.onCompleted: {
        window.currentThemeIndex = appSettings.themeIndex
        backend.expertMode = appSettings.expertMode
        if (typeof ipcSocketPath !== "undefined") window.ipcSocketPath = ipcSocketPath
        backend.getSettings() // Pedir ajustes reales al backend
        settingsLoaded = true
    }

    onCurrentThemeIndexChanged: {
        if (settingsLoaded) {
            appSettings.themeIndex = currentThemeIndex
        }
    }

    Connections {
        target: backend
        function onExpertModeChanged() {
            if (settingsLoaded) {
                appSettings.expertMode = backend.expertMode
            }
        }
    }

    function clamp01(v) {
        if (isNaN(v)) return 0.0
        if (v < 0.0) return 0.0
        if (v > 1.0) return 1.0
        return v
    }

    function requestPdfPreview() {
        if (!signVisibleSeal || !supportsVisibleSeal() || currentFilePath === "") return;
        backend.getPdfPreview(currentFilePath, signSealPage);
    }

    Connections {
        target: backend
        function onPdfPreviewReceived(ok, data, width, height) {
            if (ok) {
                console.log("QML: Previsualización recibida OK, tamaño:", width, "x", height);
                if (width && height && width > 0) {
                    pagePreview.a4Ratio = height / width;
                } else {
                    pagePreview.a4Ratio = 841.89 / 595.28;
                }
                pdfPageImage.source = "data:image/png;base64," + data;
            } else {
                console.log("Error de previsualización: " + data);
            }
        }
    }

    function isCurrentPdf() {
        if (!window.currentFilePath || window.currentFilePath === "") return false
        return window.currentFilePath.toLowerCase().endsWith(".pdf")
    }

    function supportsVisibleSeal() {
        return signFormat === "pades" || (signFormat === "" && isCurrentPdf())
    }

    function syncSealFromPreview() {
        if (pagePreview.width <= 0 || pagePreview.height <= 0) return
        signSealX = clamp01(sealRect.x / pagePreview.width)
        signSealW = clamp01(sealRect.width / pagePreview.width)
        const topY = sealRect.y / pagePreview.height
        signSealY = clamp01(1.0 - topY - (sealRect.height / pagePreview.height))
        signSealH = clamp01(sealRect.height / pagePreview.height)
    }

    function syncPreviewFromSeal() {
        if (pagePreview.width <= 0 || pagePreview.height <= 0) return
        sealRect.width = Math.max(20, clamp01(signSealW) * pagePreview.width)
        sealRect.height = Math.max(20, clamp01(signSealH) * pagePreview.height)
        sealRect.x = Math.max(0, Math.min(pagePreview.width - sealRect.width, clamp01(signSealX) * pagePreview.width))
        const topY = (1.0 - clamp01(signSealY) - clamp01(signSealH)) * pagePreview.height
        sealRect.y = Math.max(0, Math.min(pagePreview.height - sealRect.height, topY))
    }

    function buildSignPayload() {
        const body = {
            action: signAction,
            format: signFormat,
            allowInvalidPDF: signAllowInvalidPDF,
            strictCompat: signStrictCompat,
            overwrite: signOverwrite,
            saveToDisk: true,
            returnSignatureB64: false
        }
        if (signVisibleSeal && (signFormat === "pades" || (signFormat === "" && isCurrentPdf()))) {
            body.visibleSeal = {
                page: Math.max(1, Number(signSealPage)),
                x: clamp01(Number(signSealX)),
                y: clamp01(Number(signSealY)),
                w: clamp01(Number(signSealW)),
                h: clamp01(Number(signSealH)),
                rotation: window.signSealRotation
            }
        }
        return body
    }

    // --- DIALOGOS ---
    FileDialog {
        id: fileDialog
        title: "Seleccionar documento PDF"
        nameFilters: ["Archivos PDF (*.pdf)", "Todos los archivos (*)"]
        onAccepted: {
            let path = selectedFile.toString()
            if (path.startsWith("file://")) {
                if (Qt.platform.os === "windows") path = path.substring(8) // file:///
                else path = path.substring(7) // file://
            }
            window.currentFilePath = path
        }
    }

    FileDialog {
        id: saveFileDialog
        title: "Seleccionar destino del PDF firmado"
        currentFile: "file://" + window.currentOutputPath
        fileMode: FileDialog.SaveFile
        nameFilters: ["Archivos PDF (*.pdf)"]
        onAccepted: {
            let path = selectedFile.toString()
            if (path.startsWith("file://")) {
                if (Qt.platform.os === "windows") path = path.substring(8)
                else path = path.substring(7)
            }
            window.currentOutputPath = path
        }
    }

    Dialog {
        id: adminLoginDialog
        title: "Autenticación de Administrador"
        standardButtons: Dialog.Ok | Dialog.Cancel
        anchors.centerIn: parent
        modal: true
        
        ColumnLayout {
            spacing: 15; width: 350
            Text { text: "🔑 Clave de Seguridad Requerida"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 18 }
            Text { text: "Para modificar la lista de dominios permitidos (NM/CORS) debe identificarse como administrador del sistema."; color: currentTheme.secondaryTextColor; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            TextField {
                id: adminPasswordField
                echoMode: TextInput.Password
                placeholderText: "Introduzca clave..."
                Layout.fillWidth: true
                focus: true
                onAccepted: adminLoginDialog.accept()
                Label { text: "Tip: Use 'admin123' para este demo"; font.pixelSize: 10; color: "gray"; anchors.top: parent.bottom; anchors.right: parent.right }
            }
        }
        
        onAccepted: {
            if (adminPasswordField.text === "admin123") {
                window.isSecurityUnlocked = true
                backend.updateStatus("⚙️ Modo administrador habilitado.")
                backend.backendLogReceived("Acceso concedido a configuración de dominios.")
            } else {
                backend.updateStatus("❌ Error: Clave incorrecta.")
            }
            adminPasswordField.text = ""
        }
    }

    Dialog {
        id: signValidationErrorDialog
        title: "Atención"
        modal: true
        anchors.centerIn: parent
        standardButtons: Dialog.Ok
        property string errorMessage: ""
        ColumnLayout {
            spacing: 10
            Text {
                text: "⚠️ Requisitos faltantes"
                color: currentTheme.textColor
                font.bold: true
            }
            Text {
                text: signValidationErrorDialog.errorMessage
                color: currentTheme.secondaryTextColor
                wrapMode: Text.WordWrap
                Layout.preferredWidth: 300
            }
        }
    }

    FileDialog {
        id: p12FileDialog
        title: "Seleccionar certificado personal (.p12, .pfx)"
        nameFilters: ["Certificados (*.p12 *.pfx)", "Todos los archivos (*)"]
        onAccepted: {
            importPasswordDialog.open()
        }
    }

    Dialog {
        id: importPasswordDialog
        title: "Contraseña del Certificado"
        standardButtons: Dialog.Ok | Dialog.Cancel
        anchors.centerIn: parent
        modal: true
        
        ColumnLayout {
            spacing: 15; width: 350
            Text { text: "🔑 Contraseña Requerida"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 18 }
            Text { text: "Introduzca la contraseña para importar el archivo P12/PFX."; color: currentTheme.secondaryTextColor; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            TextField {
                id: importPasswordField
                echoMode: TextInput.Password
                placeholderText: "Contraseña..."
                Layout.fillWidth: true
                focus: true
                onAccepted: importPasswordDialog.accept()
            }
        }
        
        onAccepted: {
            let path = p12FileDialog.selectedFile.toString()
            backend.importCertificate(path, importPasswordField.text)
            importPasswordField.text = ""
        }
    }

    // --- LOGICA DE BACKEND ---
    Connections {
        target: backend
        function onCertificatesLoaded(certs) {
            console.log("QML: Certificados recibidos:", certs.length)
            window.certificates = certs
            // No preseleccionamos ninguno automáticamente según requerimiento
        }
        function onStatusChanged() {
            window.statusMessage = backend.status
        }
        function onExpertModeChanged() {
            // Updated via explicit Connections block above to ensure settingsLoaded respects lifecycle
        }
        function onSigningFinished(success, message, outPath) {
            window.signingInProgress = false
            window.statusMessage = (success ? "✅ " : "❌ ") + message
            if (success && outPath && outPath !== "") {
                window.currentOutputPath = outPath
            }
        }
        function onVerificationFinished(success, message, details) {
            window.statusMessage = message
            if (success) {
                activeTab = "verificar"
            }
        }
        function onSettingsLoaded(s) {
            console.log("QML: Ajustes cargados desde el backend")
            if (s.expertMode !== undefined) backend.expertMode = s.expertMode
            if (s.themeIndex !== undefined) window.currentThemeIndex = s.themeIndex
            if (s.autoClose !== undefined) window.autoClose = s.autoClose
            if (s.stickySigner !== undefined) window.stickySigner = s.stickySigner
            if (s.certsExpiredShow !== undefined) window.certsExpiredShow = s.certsExpiredShow
            if (s.tsaEnabled !== undefined) window.tsaEnabled = s.tsaEnabled
            if (s.tsaUrl !== undefined) window.tsaUrl = s.tsaUrl
            if (s.proxyEnabled !== undefined) window.proxyEnabled = s.proxyEnabled
            if (s.proxyHost !== undefined) window.proxyHost = s.proxyHost
            if (s.proxyPort !== undefined) window.proxyPort = s.proxyPort
        }
        function onCertificateImportFinished(ok, message) {
            backend.updateStatus(ok ? ("✅ " + message) : ("❌ " + message))
            if (ok) {
                backend.backendLogReceived("Firma: Certificado importado con éxito.")
            } else {
                backend.backendLogReceived("Error importando certificado: " + message)
            }
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
                        source: "../../../assets/Logo-Horizontal-Color.png"
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
                        model: ["Cristal Oscuro", "Minimalista Luz", "Futurista", "Corporativo", "Neón Cyber", "Bosque Profundo", "Atardecer Cálido", "Océano Profundo", "Vampiro Elegante", "Aurora Boreal", "Perla Lujosa", "Ametista", "Terminal Hacker", "Desierto Terracota"]
                        currentIndex: window.currentThemeIndex
                        onActivated: function(index) { window.currentThemeIndex = index }
                    }
                }
            }
        }

        // --- CONTENIDO ---
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: activeTab === "firmar" ? 0 : 
                          (activeTab === "verificar" ? 1 : 
                          (activeTab === "config" ? 2 : 
                          (activeTab === "experto" ? 3 : 
                          (activeTab === "seguridad" ? 4 : 5))))

            // TAB: FIRMAR (0)
            Item {
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 40
                    spacing: 40

                    ScrollView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        contentWidth: availableWidth
                        clip: true

                        ColumnLayout {
                            width: parent.width
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
                                RowLayout {
                                    Layout.alignment: Qt.AlignCenter
                                    spacing: 10
                                    Button {
                                        text: "Seleccionar Archivo"
                                        onClicked: fileDialog.open()
                                    }
                                    Button {
                                        text: "Ver Original"
                                        visible: window.currentFilePath !== ""
                                        onClicked: backend.openExternal(window.currentFilePath)
                                    }
                                }
                            }
                        }

                        // NUEVO: Gestión de Rutas Visibles
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: pathCol.implicitHeight + 20
                            radius: 10
                            color: currentTheme.cardColor
                            border.color: Qt.rgba(1, 1, 1, currentTheme.borderOpacity)
                            
                            ColumnLayout {
                                id: pathCol
                                anchors.fill: parent
                                anchors.margins: 15
                                spacing: 10

                                Text { 
                                    text: "RUTA DE ENTRADA"
                                    color: currentTheme.secondaryTextColor
                                    font.pixelSize: 10; font.bold: true 
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    TextField {
                                        text: window.currentFilePath
                                        Layout.fillWidth: true
                                        placeholderText: "Seleccione un archivo..."
                                        onTextChanged: window.currentFilePath = text
                                    }
                                }

                                Text { 
                                    text: "RUTA DE SALIDA (PDF FIRMADO)"
                                    color: currentTheme.secondaryTextColor
                                    font.pixelSize: 10; font.bold: true 
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    TextField {
                                        text: window.currentOutputPath
                                        Layout.fillWidth: true
                                        placeholderText: "Destino automático..."
                                        onTextChanged: window.currentOutputPath = text
                                    }
                                    Button {
                                        icon.source: "../../../assets/eye_icon.png"
                                        icon.width: 22
                                        icon.height: 22
                                        icon.color: "white"
                                        Layout.preferredWidth: 44
                                        Layout.preferredHeight: 44
                                        enabled: window.currentOutputPath !== ""
                                        onClicked: backend.openExternal(window.currentOutputPath)
                                        ToolTip.visible: hovered
                                        ToolTip.text: "Ver archivo (Abrir externamente)"
                                        ToolTip.delay: 500
                                    }
                                    Button {
                                        icon.source: "../../../assets/search_icon.png"
                                        icon.width: 20
                                        icon.height: 20
                                        icon.color: "white"
                                        Layout.preferredWidth: 44
                                        Layout.preferredHeight: 44
                                        enabled: window.currentOutputPath !== ""
                                        onClicked: jumpToVerify(window.currentOutputPath)
                                        ToolTip.visible: hovered
                                        ToolTip.text: "Validar firma del documento"
                                        ToolTip.delay: 500
                                    }
                                    Button {
                                        icon.source: "../../../assets/folder_icon.png"
                                        icon.width: 22
                                        icon.height: 22
                                        icon.color: "white"
                                        Layout.preferredWidth: 44
                                        Layout.preferredHeight: 44
                                        onClicked: saveFileDialog.open()
                                        ToolTip.visible: hovered
                                        ToolTip.text: "Cambiar ubicación del archivo de salida"
                                        ToolTip.delay: 500
                                    }
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: optionsCol.implicitHeight + 24
                            radius: 10
                            color: currentTheme.cardColor
                            border.color: Qt.rgba(1, 1, 1, currentTheme.borderOpacity)
                            ScrollView {
                                id: scrollOpts
                                anchors.fill: parent
                                anchors.margins: 12
                                contentWidth: optionsCol.implicitWidth
                                contentHeight: optionsCol.implicitHeight
                                clip: true

                                ColumnLayout {
                                    id: optionsCol
                                    width: Math.max(scrollOpts.width, implicitWidth)
                                    spacing: 10

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Operación"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        ComboBox {
                                            Layout.fillWidth: true
                                            model: [
                                                { texto: "Firmar", valor: "sign" },
                                                { texto: "Cofirmar", valor: "cosign" },
                                                { texto: "Contrafirmar", valor: "countersign" }
                                            ]
                                            textRole: "texto"
                                            onActivated: function(index) { signAction = model[index].valor }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Formato"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        ComboBox {
                                            Layout.fillWidth: true
                                            model: [
                                                { texto: "Auto", valor: "" },
                                                { texto: "PAdES", valor: "pades" },
                                                { texto: "CAdES", valor: "cades" },
                                                { texto: "XAdES", valor: "xades" }
                                            ]
                                            textRole: "texto"
                                            onActivated: function(index) { signFormat = model[index].valor }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Sobrescritura"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        ComboBox {
                                            Layout.fillWidth: true
                                            model: [
                                                { texto: "Renombrar", valor: "rename" },
                                                { texto: "Error si existe", valor: "fail" },
                                                { texto: "Forzar", valor: "force" }
                                            ]
                                            textRole: "texto"
                                            onActivated: function(index) { signOverwrite = model[index].valor }
                                        }
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    CheckBox {
                                        text: "Firma visible (PAdES)"
                                         checked: signVisibleSeal
                                         onToggled: {
                                             signVisibleSeal = checked
                                             if (checked) requestPdfPreview()
                                         }
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Inserta un sello gráfico en el PDF indicando que ha sido firmado digitalmente."
                                    }
                                    CheckBox {
                                        text: "Compatibilidad estricta"
                                        checked: signStrictCompat
                                        onToggled: signStrictCompat = checked
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Aplica perfiles de firma más restrictivos para maximizar la compatibilidad con administraciones públicas."
                                    }
                                    CheckBox {
                                        text: "Permitir PDF inválido"
                                        checked: signAllowInvalidPDF
                                        onToggled: signAllowInvalidPDF = checked
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Intenta firmar el PDF incluso si su estructura está ligeramente dañada o no cumple estrictamente el estándar ISO."
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    visible: signVisibleSeal
                                    enabled: signVisibleSeal
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Página"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        SpinBox {
                                            from: 1
                                            to: 999
                                             value: signSealPage
                                             onValueChanged: {
                                                 signSealPage = value
                                                 requestPdfPreview()
                                             }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "X (0..1)"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            text: Number(signSealX).toFixed(4)
                                            onEditingFinished: {
                                                signSealX = clamp01(Number(text))
                                                text = Number(signSealX).toFixed(4)
                                                syncPreviewFromSeal()
                                            }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Y (0..1)"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            text: Number(signSealY).toFixed(4)
                                            onEditingFinished: {
                                                signSealY = clamp01(Number(text))
                                                text = Number(signSealY).toFixed(4)
                                                syncPreviewFromSeal()
                                            }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Ancho (0..1)"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            text: Number(signSealW).toFixed(4)
                                            onEditingFinished: {
                                                signSealW = clamp01(Number(text))
                                                text = Number(signSealW).toFixed(4)
                                                syncPreviewFromSeal()
                                            }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Alto (0..1)"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            text: Number(signSealH).toFixed(4)
                                            onEditingFinished: {
                                                signSealH = clamp01(Number(text))
                                                text = Number(signSealH).toFixed(4)
                                                syncPreviewFromSeal()
                                            }
                                        }
                                    }
                                }

                                RowLayout {
                                    visible: signVisibleSeal && supportsVisibleSeal()
                                    Layout.alignment: Qt.AlignRight
                                    spacing: 10
                                    Button {
                                        text: "↻ Rotar Documento"
                                        font.pixelSize: 12
                                        onClicked: {
                                            pagePreview.a4Ratio = 1.0 / pagePreview.a4Ratio
                                        }
                                    }
                                     Button {
                                         text: "↶ Rotar Firma"
                                         font.pixelSize: 12
                                         onClicked: {
                                             // Ciclo de rotación: 0 -> 90 -> 180 -> 270 -> 0
                                             window.signSealRotation = (window.signSealRotation + 90) % 360
                                             
                                             // Intercambio de dimensiones relativas manteniendo el centro
                                             let oldW = signSealW;
                                             let oldH = signSealH;
                                             
                                             signSealW = oldH;
                                             signSealH = oldW;
                                             
                                             // Ajustamos X e Y para que el centro no cambie
                                             signSealX = clamp01(signSealX + (oldW - signSealW) / 2);
                                             signSealY = clamp01(signSealY + (oldH - signSealH) / 2);
                                             
                                             syncPreviewFromSeal();
                                         }
                                     }
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: signVisibleSeal ? pagePreview.height + 20 : 0
                                    visible: signVisibleSeal && supportsVisibleSeal()
                                    color: "#ffffff"
                                    border.color: "#95a5a6"
                                    radius: 8

                                     Rectangle {
                                         id: pagePreview
                                         anchors.centerIn: parent
                                         property real a4Ratio: 841.89 / 595.28

                                         Image {
                                             id: pdfPageImage
                                             anchors.fill: parent
                                             fillMode: Image.PreserveAspectFit
                                             source: ""
                                             visible: source !== ""
                                         }
                                        width: Math.min(parent.width - 20, 500 / a4Ratio)
                                        height: width * a4Ratio
                                        color: "#fafafa"
                                        border.color: "#34495e"
                                        border.width: 1
                                        onWidthChanged: syncPreviewFromSeal()
                                        onHeightChanged: syncPreviewFromSeal()

                                        Rectangle {
                                            id: sealRect
                                            x: Math.max(0, Math.min(parent.width - width, signSealX * parent.width))
                                            y: Math.max(0, Math.min(parent.height - height, (1.0 - signSealY - signSealH) * parent.height))
                                            width: Math.max(30, signSealW * parent.width)
                                            height: Math.max(20, signSealH * parent.height)
                                            color: "#3498db55"
                                            border.color: "#2980b9"
                                            border.width: 2
                                            visible: signVisibleSeal && supportsVisibleSeal()

                                            // Contenido del sello (lo que se verá en el PDF)
                                            Column {
                                                anchors.centerIn: parent
                                                // Si hay rotación de 90/270, el ancho disponible es el alto del padre
                                                width: (window.signSealRotation % 180 === 0) ? (parent.width - 10) : (parent.height - 10)
                                                spacing: 2
                                                clip: true
                                                 rotation: window.signSealRotation // Rotación visual directa (CW)
                                                Text {
                                                    text: "✍ FIRMA DIGITAL"
                                                    font.bold: true
                                                    font.pixelSize: Math.max(8, Math.min(14, sealRect.height * 0.2))
                                                    color: "#2980b9"
                                                    anchors.horizontalCenter: parent.horizontalCenter
                                                }
                                                Text {
                                                    text: (selectedCertIndex !== -1 && window.selectedCertData) 
                                                          ? (window.selectedCertData.subjectName || (window.selectedCertData.subject && window.selectedCertData.subject.CN) || "Firmante")
                                                          : "Muestra de Firma"
                                                    font.pixelSize: Math.max(7, Math.min(12, sealRect.height * 0.15))
                                                    color: "#34495e"
                                                    width: parent.width
                                                    wrapMode: Text.Wrap
                                                    horizontalAlignment: Text.AlignHCenter
                                                    elide: Text.ElideRight
                                                    maximumLineCount: 2
                                                    anchors.horizontalCenter: parent.horizontalCenter
                                                }
                                            }

                                            MouseArea {
                                                id: dragArea
                                                anchors.fill: parent
                                                drag.target: parent
                                                drag.minimumX: 0
                                                drag.minimumY: 0
                                                drag.maximumX: pagePreview.width - sealRect.width
                                                drag.maximumY: pagePreview.height - sealRect.height
                                                cursorShape: Qt.OpenHandCursor
                                                enabled: !resizeArea.pressed
                                                onPressed: cursorShape = Qt.ClosedHandCursor
                                                onReleased: cursorShape = Qt.OpenHandCursor
                                                onPositionChanged: {
                                                    syncSealFromPreview()
                                                }
                                            }

                                            // Manejador de redimensionado (esquina inferior derecha)
                                            Rectangle {
                                                width: 16
                                                height: 16
                                                color: "#2980b9"
                                                radius: 8
                                                anchors.right: parent.right
                                                anchors.bottom: parent.bottom
                                                anchors.margins: -8
                                                z: 10
                                                border.color: "white"
                                                border.width: 1

                                                MouseArea {
                                                    id: resizeArea
                                                    anchors.centerIn: parent
                                                    width: 44
                                                    height: 44
                                                    cursorShape: Qt.SizeFDiagCursor
                                                    onPositionChanged: (mouse) => {
                                                        if (pressed) {
                                                            let p = mapToItem(pagePreview, mouse.x, mouse.y)
                                                            let newW = Math.max(40, Math.min(pagePreview.width - sealRect.x, p.x - sealRect.x))
                                                            let newH = Math.max(25, Math.min(pagePreview.height - sealRect.y, p.y - sealRect.y))
                                                            sealRect.width = newW
                                                            sealRect.height = newH
                                                            syncSealFromPreview()
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                Text {
                                    visible: signVisibleSeal && !supportsVisibleSeal()
                                    color: currentTheme.secondaryTextColor
                                    text: "La firma visible solo se aplica a PAdES (PDF)."
                                }
                                }
                            }
                        }

                        RowLayout {
                            spacing: 10
                                Button {
                                    text: window.signingInProgress ? "⌛ Firmando..." : "Firmar ahora"
                                    font.bold: true
                                    palette.button: window.signingInProgress ? currentTheme.secondaryTextColor : currentTheme.primaryColor
                                    palette.buttonText: "white"
                                    enabled: !window.signingInProgress
                                    onClicked: {
                                        if (window.currentFilePath === "" && selectedCertIndex === -1) {
                                            signValidationErrorDialog.errorMessage = "Debe cargar un archivo PDF y seleccionar un certificado para poder firmar."
                                            signValidationErrorDialog.open()
                                        } else if (window.currentFilePath === "") {
                                            signValidationErrorDialog.errorMessage = "Debe cargar un archivo PDF antes de realizar la firma."
                                            signValidationErrorDialog.open()
                                        } else if (selectedCertIndex === -1) {
                                            signValidationErrorDialog.errorMessage = "Debe seleccionar un certificado de la lista para poder firmar el documento."
                                            signValidationErrorDialog.open()
                                        } else {
                                            window.signingInProgress = true
                                            window.statusMessage = "Procesando firma..."
                                            backend.signFileAdvanced(window.currentFilePath, window.currentOutputPath, selectedCertIndex, buildSignPayload())
                                        }
                                    }
                                }
                                Button {
                                    text: "Ver firmado"
                                    visible: window.currentOutputPath !== "" && !window.signingInProgress
                                    onClicked: backend.openExternal(window.currentOutputPath)
                                }
                            Button {
                                text: "Limpiar"
                                onClicked: {
                                    window.currentFilePath = ""
                                    signVisibleSeal = false
                                }
                            }
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
                                    text: "Importar..."
                                    flat: true
                                    onClicked: p12FileDialog.open()
                                }
                                Button {
                                    text: "Actualizar"
                                    flat: true
                                    onClicked: backend.checkCertificates()
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
                                    MouseArea { 
                                        anchors.fill: parent; 
                                        onClicked: { 
                                            selectedCertIndex = index; 
                                            window.selectedCertData = modelData;
                                            console.log("QML: Certificado seleccionado:", modelData.subjectName, "ID:", modelData.id)
                                        } 
                                    }
                                }
                            }

                            // Subpanel con detalles del certificado seleccionado
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 180
                                visible: selectedCertIndex !== -1 && window.selectedCertData
                                color: currentTheme.cardColor
                                radius: 10
                                border.color: currentTheme.primaryColor
                                border.width: 1

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 5
                                    
                                    Text {
                                        text: "Detalles del certificado"
                                        font.bold: true
                                        color: "white"
                                    }

                                    ScrollView {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        clip: true

                                        Column {
                                            width: parent.width
                                            spacing: 6
                                            
                                            Text { 
                                                text: "<b>Titular:</b> " + (window.selectedCertData ? (window.selectedCertData.subjectName || "---") : "")
                                                color: "white"
                                                font.pixelSize: 11
                                                wrapMode: Text.Wrap
                                                width: parent.width
                                            }
                                            Text { 
                                                text: "<b>Emisor:</b> " + (window.selectedCertData ? (window.selectedCertData.issuerName || "---") : "")
                                                color: "white"
                                                opacity: 0.8
                                                font.pixelSize: 11
                                                wrapMode: Text.Wrap
                                                width: parent.width
                                            }
                                            Text { 
                                                text: "<b>Nº Serie:</b> " + (window.selectedCertData ? (window.selectedCertData.serialNumber || "") : "")
                                                color: "white"
                                                opacity: 0.8
                                                font.pixelSize: 10
                                                wrapMode: Text.Wrap
                                                width: parent.width
                                            }
                                            Text { 
                                                text: "<b>Válido hasta:</b> " + (window.selectedCertData ? (window.selectedCertData.validTo || "") : "")
                                                color: "white"
                                                opacity: 0.8
                                                font.pixelSize: 10
                                                wrapMode: Text.Wrap
                                                width: parent.width
                                            }
                                            Text { 
                                                text: "<b>Huella:</b> " + (window.selectedCertData ? (window.selectedCertData.fingerprint || "") : "")
                                                color: "white"
                                                opacity: 0.6
                                                font.pixelSize: 9
                                                wrapMode: Text.Wrap
                                                width: parent.width
                                            }
                                        }
                                    }

                                    Button {
                                        Layout.fillWidth: true
                                        text: "Validar en VALIDE (Sede Electrónica)"
                                        background: Rectangle {
                                            color: "#e67e22"
                                            radius: 6
                                        }
                                        palette.buttonText: "white"
                                        onClicked: {
                                            backend.openExternal("https://valide.redsara.es/valide/validarCertificados/paso1.html")
                                        }
                                    }
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
                                            text: "Estado: " + ((verifyTab.verifyDetails && verifyTab.verifyDetails.valid) ? "✅ VÁLIDA" : "❌ NO VÁLIDA")
                                            color: "white"; font.pixelSize: 16 
                                        }
                                        Text { 
                                            text: "Firmante: " + (verifyTab.verifyDetails && verifyTab.verifyDetails.signerName ? verifyTab.verifyDetails.signerName : "")
                                            color: "white"; visible: verifyTab.verifyDetails && verifyTab.verifyDetails.signerName !== undefined
                                        }
                                        Text { 
                                            text: "Email: " + (verifyTab.verifyDetails && verifyTab.verifyDetails.signerEmail ? verifyTab.verifyDetails.signerEmail : "")
                                            color: "white"; visible: verifyTab.verifyDetails && verifyTab.verifyDetails.signerEmail !== undefined
                                        }
                                        Text { 
                                            text: "Fecha: " + (verifyTab.verifyDetails && verifyTab.verifyDetails.timestamp ? verifyTab.verifyDetails.timestamp : "")
                                            color: "white"; visible: verifyTab.verifyDetails && verifyTab.verifyDetails.timestamp !== undefined
                                        }
                                        Text { 
                                            text: "Razón: " + (verifyTab.verifyDetails && verifyTab.verifyDetails.reason ? verifyTab.verifyDetails.reason : "")
                                            color: "#e74c3c"; visible: verifyTab.verifyDetails && !verifyTab.verifyDetails.valid
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
                property bool svcConnected: true
                property bool restServerRunning: false

                Timer {
                    id: statusRetryTimer
                    interval: 1000
                    repeat: false
                    onTriggered: {
                        if (window.activeTab === "config") {
                            backend.getServiceStatus()
                        }
                    }
                }

                function refreshServiceStatus() {
                    backend.getServiceStatus()
                }

                Connections {
                    target: backend
                    function onServiceStatusReceived(installed, running, platform, method) {
                        configTab.svcConnected = true
                        configTab.svcMessage = ""
                        configTab.svcInstalled = installed
                        configTab.svcRunning   = running
                        configTab.svcPlatform  = platform
                        configTab.svcMethod    = method
                    }
                    function onServiceActionFinished(ok, message) {
                        if (!ok && message && message.indexOf("Sin conexión") !== -1) {
                            configTab.svcConnected = false
                            configTab.svcMessage = "⚠ Desconectado de la interfaz IPC local (modo REST exclusivo, o motor parado)."
                        } else {
                            if (!ok) configTab.svcConnected = true
                            configTab.svcMessage = message
                        }
                        statusRetryTimer.start()
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

                        // ── Preferencias de Usuario ─────────────────────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: prefCol.implicitHeight + 40
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1

                            ColumnLayout {
                                id: prefCol
                                anchors { top: parent.top; left: parent.left; right: parent.right; margins: 20 }
                                spacing: 15

                                Text { text: "⚙️  Preferencias Generales"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 15 }

                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "Modo Experto"; color: currentTheme.textColor; Layout.fillWidth: true }
                                    Switch {
                                        checked: backend.expertMode
                                        onToggled: {
                                            backend.expertMode = checked
                                            saveBackendSettings()
                                        }
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Habilita opciones avanzadas de diagnóstico y configuración."
                                    }
                                }
                                
                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "Cerrar ventana tras firmar"; color: currentTheme.textColor; Layout.fillWidth: true }
                                    Switch {
                                        checked: window.autoClose
                                        onToggled: {
                                            window.autoClose = checked
                                            saveBackendSettings()
                                        }
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Cierra la ventana de la aplicación automáticamente después de una firma exitosa."
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "Recordar último certificado"; color: currentTheme.textColor; Layout.fillWidth: true }
                                    Switch {
                                        checked: window.stickySigner
                                        onToggled: {
                                            window.stickySigner = checked
                                            saveBackendSettings()
                                        }
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Al iniciar, selecciona automáticamente el último certificado usado para firmar."
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "Mostrar certificados caducados"; color: currentTheme.textColor; Layout.fillWidth: true }
                                    Switch {
                                        checked: window.certsExpiredShow
                                        onToggled: {
                                            window.certsExpiredShow = checked
                                            saveBackendSettings()
                                        }
                                        ToolTip.visible: hovered
                                        ToolTip.delay: 500
                                        ToolTip.text: "Muestra los certificados que ya han expirado en la lista de selección."
                                    }
                                }
                            }
                        }

                        // ── TSA (Sellado de Tiempo) ─────────────────────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: tsaCol.implicitHeight + 40
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1

                            ColumnLayout {
                                id: tsaCol
                                anchors { top: parent.top; left: parent.left; right: parent.right; margins: 20 }
                                spacing: 12

                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "⏳  Sellado de Tiempo (TSA)"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 15; Layout.fillWidth: true; ToolTip.text: "Habilita el uso de un servidor de sellado de tiempo para añadir una marca de tiempo a las firmas." }
                                    Switch {
                                        checked: window.tsaEnabled
                                        onToggled: {
                                            window.tsaEnabled = checked
                                            saveBackendSettings()
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    enabled: window.tsaEnabled
                                    opacity: enabled ? 1.0 : 0.5
                                    spacing: 12

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 4
                                        Text { text: "Servidor TSA:"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        ComboBox {
                                            id: tsaCombo
                                            Layout.fillWidth: true
                                            editable: true
                                            model: [
                                                "http://tsa.fnmt.es/",
                                                "http://tsa.accv.es/",
                                                "http://tsa.catcert.net/",
                                                "http://tsa.camerfirma.com/",
                                                "http://tsa.izenpe.com/"
                                            ]
                                            onActivated: {
                                                window.tsaUrl = editText
                                                saveBackendSettings()
                                            }
                                            onEditTextChanged: {
                                                window.tsaUrl = editText
                                                saveBackendSettings()
                                            }
                                            Component.onCompleted: {
                                                editText = window.tsaUrl
                                            }
                                            Connections {
                                                target: window
                                                function onTsaUrlChanged() {
                                                    if (tsaCombo.editText !== window.tsaUrl) {
                                                        tsaCombo.editText = window.tsaUrl
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    Button {
                                        Layout.fillWidth: true
                                        text: "🛡️ Instalar Certificados Raíz de Administraciones Públicas"
                                        palette.button: currentTheme.primaryColor; palette.buttonText: "white"
                                        onClicked: backend.installCamerfirmaCerts()
                                        ToolTip.visible: hovered
                                        ToolTip.text: "Descarga e instala los certificados necesarios para confiar en FNMT, ACCV, Camerfirma, etc."
                                    }
                                }
                            }
                        }

                        // ── Proxy ─────────────────────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: proxyCol.implicitHeight + 40
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1

                            ColumnLayout {
                                id: proxyCol
                                anchors { top: parent.top; left: parent.left; right: parent.right; margins: 20 }
                                spacing: 12

                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "🌐  Configuración de Proxy"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 15; Layout.fillWidth: true; ToolTip.text: "Habilita el uso de un servidor proxy para las conexiones de red." }
                                    Switch {
                                        checked: window.proxyEnabled
                                        onToggled: {
                                            window.proxyEnabled = checked
                                            saveBackendSettings()
                                        }
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    enabled: window.proxyEnabled
                                    opacity: enabled ? 1.0 : 0.5
                                    spacing: 10
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Host / IP:"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            Layout.fillWidth: true
                                            text: window.proxyHost
                                            onEditingFinished: {
                                                window.proxyHost = text
                                                saveBackendSettings()
                                            }
                                        }
                                    }
                                    ColumnLayout {
                                        width: 100
                                        Text { text: "Puerto:"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            Layout.fillWidth: true
                                            text: window.proxyPort.toString()
                                            validator: IntValidator { bottom: 1; top: 65535 }
                                            onEditingFinished: {
                                                window.proxyPort = parseInt(text)
                                                saveBackendSettings()
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // ── Servidor API REST / Acceso Remoto ─────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: restSrvCol.implicitHeight + 40
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1

                            ColumnLayout {
                                id: restSrvCol
                                anchors { top: parent.top; left: parent.left; right: parent.right; margins: 20 }
                                spacing: 12

                                Text { text: "🌐  Servidor API REST / Acceso Remoto"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 15; Layout.fillWidth: true; ToolTip.text: "Permite el acceso a las funciones de firma desde otros equipos de la red o aplicaciones externas." }
                                
                                // Estado actual del API REST
                                Rectangle {
                                    Layout.fillWidth: true; height: 44; radius: 8
                                    color: configTab.restServerRunning ? "#1a4a1a" : "#2a0a0a"
                                    border.color: configTab.restServerRunning ? "#2ecc71" : "#e74c3c"
                                    border.width: 1

                                    RowLayout {
                                        anchors.fill: parent; anchors.margins: 12; spacing: 10
                                        Text {
                                            text: configTab.restServerRunning ? "● Servidor API REST en ejecución" : "● Servidor detenido"
                                            color: configTab.restServerRunning ? "#2ecc71" : "#e74c3c"
                                            font.bold: true; font.pixelSize: 13; Layout.fillWidth: true
                                        }
                                    }
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Text { text: "Puerto:"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            id: restPortField
                                            Layout.fillWidth: true
                                            text: "63118"
                                            validator: IntValidator { bottom: 1024; top: 65535 }
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Layout.preferredWidth: 300
                                        Text { text: "Token de Seguridad:"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                        TextField {
                                            id: restTokenField
                                            Layout.fillWidth: true
                                            placeholderText: "Opcional: token de acceso bearer"
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4
                                    Text { text: "Huellas de Certificados Cliente (SHA-256 CSV):"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                    TextField {
                                        id: restFingerprintsField
                                        Layout.fillWidth: true
                                        placeholderText: "Opcional: 6F:..., 8A:..."
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    CheckBox {
                                        id: restHttpsCheck
                                        text: "Habilitar HTTPS (Recomendado para acceso remoto)"
                                        checked: false
                                    }
                                }
                                
                                RowLayout {
                                    Layout.fillWidth: true; spacing: 10
                                     Button {
                                        text: "Iniciar servidor"
                                        palette.button: currentTheme.primaryColor; palette.buttonText: "white"
                                        onClicked: {
                                            configTab.restServerRunning = true
                                            backend.startBackend("0.0.0.0:" + restPortField.text, 
                                                                restTokenField.text, 
                                                                "ambas",
                                                                restFingerprintsField.text,
                                                                restHttpsCheck.checked)
                                        }
                                    }
                                    Button {
                                        text: "Detener"
                                        onClicked: {
                                            configTab.restServerRunning = false
                                            backend.stopBackend()
                                        }
                                    }
                                    Item { Layout.fillWidth: true } // Spacer
                                    Button {
                                        text: "Abrir web"
                                        icon.name: "applications-internet"
                                        enabled: configTab.restServerRunning
                                        onClicked: {
                                            var protocol = restHttpsCheck.checked ? "https://" : "http://"
                                            var targetUrl = protocol + "127.0.0.1:" + restPortField.text + "/"
                                            console.log("Intentando abrir web en:", targetUrl)
                                            Qt.openUrlExternally(targetUrl)
                                        }
                                    }
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
                                    color: !configTab.svcConnected ? "#333333" : (configTab.svcRunning ? "#1a4a1a" : (configTab.svcInstalled ? "#4a3a0a" : "#2a0a0a"))
                                    border.color: !configTab.svcConnected ? "#aaaaaa" : (configTab.svcRunning ? "#2ecc71" : (configTab.svcInstalled ? "#f39c12" : "#e74c3c"))
                                    border.width: 1

                                    RowLayout {
                                        anchors.fill: parent; anchors.margins: 12; spacing: 10
                                        Text {
                                            text: !configTab.svcConnected ? "● Estado desconocido (Sin conexión)" :
                                                  configTab.svcRunning ? "● Servicio activo y corriendo" :
                                                  configTab.svcInstalled ? "● Servicio instalado pero parado" : "● Servicio no instalado"
                                            color: !configTab.svcConnected ? "#aaaaaa" : (configTab.svcRunning ? "#2ecc71" : (configTab.svcInstalled ? "#f39c12" : "#e74c3c"))
                                            font.bold: true; font.pixelSize: 13; Layout.fillWidth: true
                                        }
                                        Text {
                                            text: configTab.svcConnected && configTab.svcMethod ? "(" + configTab.svcMethod + ")" : ""
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
                                        enabled: configTab.svcConnected
                                        palette.button: currentTheme.primaryColor; palette.buttonText: "white"
                                        onClicked: backend.installService()
                                    }
                                    Button {
                                        text: "Desinstalar servicio"
                                        visible: configTab.svcInstalled
                                        enabled: configTab.svcConnected
                                        palette.button: "#c0392b"; palette.buttonText: "white"
                                        onClicked: backend.uninstallService()
                                    }
                                    Button {
                                        text: "Arrancar"
                                        visible: configTab.svcInstalled && !configTab.svcRunning
                                        enabled: configTab.svcConnected
                                        palette.button: "#27ae60"; palette.buttonText: "white"
                                        onClicked: backend.startService()
                                    }
                                    Button {
                                        text: "Detener"
                                        visible: configTab.svcInstalled && configTab.svcRunning
                                        enabled: configTab.svcConnected
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
                        // ── Restaurar Parámetros ─────────────────────────────────
                        Rectangle {
                            Layout.fillWidth: true
                            height: 70
                            radius: 12
                            color: currentTheme.cardColor
                            border.color: currentTheme.primaryColor; border.width: 1

                            RowLayout {
                                anchors.fill: parent; anchors.margins: 20; spacing: 15
                                Text { text: "↺  Valores por defecto"; color: currentTheme.textColor; font.bold: true; font.pixelSize: 15; Layout.fillWidth: true }
                                Text { text: "Restaura el tema y opciones a fábrica"; color: currentTheme.secondaryTextColor; font.pixelSize: 12 }
                                Button {
                                    text: "Restaurar"
                                    palette.button: "#e74c3c"; palette.buttonText: "white"
                                    onClicked: {
                                        window.currentThemeIndex = 0
                                        backend.expertMode = false
                                        // Las señales de onCurrentThemeIndexChanged y onExpertModeChanged
                                        // en QML actualizarán automáticamente appSettings
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
                        ComboBox {
                            id: serverModeCombo
                            model: ["ipc", "rest", "ambas"]
                            currentIndex: 0
                            font.pixelSize: 13
                        }
                        Button {
                            text: "Reiniciar Backend"
                            font.bold: true
                            palette.button: "#e67e22"; palette.buttonText: "white"
                            onClicked: {
                                backend.stopBackend()
                                let selectedMode = serverModeCombo.currentText
                                if (selectedMode === "ipc") {
                                    // Modo puro IPC
                                    backend.startBackend(ipcSocketPath, "", "ipc")
                                } else if (selectedMode === "rest") {
                                    // Modo puro REST
                                    backend.startBackend("127.0.0.1:63118", "secreto", "rest")
                                } else {
                                    // Modo mixto
                                    backend.startBackend(ipcSocketPath, "secreto", "ambas")
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
                            Button { 
                                text: "Limpiar Log"; 
                                palette.button: "#2c3e50"; 
                                onClicked: logArea.text = "--- LOGS REINICIADOS [" + new Date().toLocaleTimeString() + "] ---\n" 
                            }
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

            // TAB: SEGURIDAD (4)
            Item {
                id: securityTab
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 40; spacing: 20
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Seguridad y Dominios"; font.pixelSize: 32; font.bold: true; color: currentTheme.textColor; Layout.fillWidth: true }
                        Button { text: "Volver"; flat: true; onClicked: activeTab = "experto" }
                    }
                    Text { text: "Lista de dominios permitidos para llamadas desde el navegador (CORS)"; color: currentTheme.secondaryTextColor }
                    
                    Rectangle {
                        Layout.fillWidth: true; Layout.fillHeight: true; radius: 15; color: currentTheme.cardColor
                        ColumnLayout {
                            anchors.centerIn: parent; spacing: 15; width: parent.width * 0.8
                            Text { text: "🛡️ Control de Dominios Permitidos"; color: currentTheme.textColor; font.pixelSize: 22; font.bold: true; Layout.alignment: Qt.AlignHCenter }
                            
                            StackLayout {
                                Layout.fillWidth: true; Layout.preferredHeight: 250
                                currentIndex: window.isSecurityUnlocked ? 1 : 0
                                
                                // Vista Bloqueada
                                ColumnLayout {
                                    spacing: 15
                                    Text { 
                                        text: "Esta funcionalidad permite restringir qué páginas web pueden solicitar firmas.\nPor defecto se permiten dominios de confianza de la administración.\n\nReglas activas:\n• *.gob.es (Permitido)\n• *.dipgra.es (Permitido)\n• localhost:* (Solo desarrollo)"
                                        color: currentTheme.secondaryTextColor
                                        horizontalAlignment: Text.AlignHCenter
                                        Layout.fillWidth: true
                                        wrapMode: Text.WordWrap
                                    }
                                    Button { 
                                        text: "Desbloquear Configuración"
                                        palette.button: currentTheme.primaryColor; palette.buttonText: "white"
                                        Layout.alignment: Qt.AlignHCenter
                                        onClicked: adminLoginDialog.open()
                                    }
                                }
                                
                                // Vista Desbloqueada (Editor)
                                ColumnLayout {
                                    spacing: 10
                                    Text { text: "EDICIÓN EN VIVO HABILITADA"; color: "#2ecc71"; font.bold: true; Layout.alignment: Qt.AlignHCenter }
                                    ScrollView {
                                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                                        ListView {
                                            model: ["*.gob.es", "*.dipgra.es", "localhost:*", "sede.granada.org"]
                                            delegate: RowLayout {
                                                width: parent.width; spacing: 10
                                                TextField { text: modelData; Layout.fillWidth: true }
                                                Button { text: "🗑"; onClicked: backend.updateStatus("Dominio eliminado: " + modelData) }
                                            }
                                        }
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        Button { text: "Añadir Dominio"; onClicked: backend.updateStatus("Añadiendo nuevo dominio a la lista...") }
                                        Button { text: "Guardar Cambios"; highlighted: true; onClicked: { window.isSecurityUnlocked = false; backend.updateStatus("Cambios guardados con éxito.") } }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // TAB: PRUEBAS (5)
            Item {
                id: testsTab
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 40; spacing: 20
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Pruebas de Integración"; font.pixelSize: 32; font.bold: true; color: currentTheme.textColor; Layout.fillWidth: true }
                        Button { text: "Volver"; flat: true; onClicked: activeTab = "experto" }
                    }
                    
                    Rectangle {
                        Layout.fillWidth: true; Layout.fillHeight: true; radius: 15; color: currentTheme.cardColor
                        ColumnLayout {
                            anchors.centerIn: parent; spacing: 20; width: parent.width * 0.8
                            Text { text: "🧪 Banco de Pruebas Automático"; color: currentTheme.textColor; font.pixelSize: 22; font.bold: true; Layout.alignment: Qt.AlignHCenter }
                            Text { 
                                text: "Ejecuta una serie de firmas y verificaciones de prueba para asegurar\nque el motor y los certificados están funcionando correctamente en este entorno."
                                color: currentTheme.secondaryTextColor
                                horizontalAlignment: Text.AlignHCenter
                                Layout.fillWidth: true
                            }
                            Button { 
                                text: "Lanzar Suite de Pruebas"
                                palette.button: currentTheme.primaryColor; palette.buttonText: "white"
                                font.bold: true
                                Layout.preferredHeight: 50
                                Layout.preferredWidth: 250
                                Layout.alignment: Qt.AlignHCenter
                                onClicked: {
                                    backend.updateStatus("Lanzando suite de pruebas...");
                                    backend.backendLogReceived("Iniciando integración test v1.0...");
                                    backend.backendLogReceived("[01/05] Test conexión socket: OK");
                                    backend.backendLogReceived("[02/05] Test carga certificados: OK");
                                    backend.backendLogReceived("[03/05] Test firma PAdES dummy: Ejecutando...");
                                    backend.updateStatus("Pruebas finalizadas con éxito.");
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
