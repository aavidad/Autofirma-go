/**
 * AutoFirma Web Console Logic
 */

const AppState = {
    apiUrl: (window.location && /^https?:$/i.test(window.location.protocol))
        ? window.location.origin
        : 'http://127.0.0.1:63118',
    apiToken: '',
    connected: false,
    selectedFile: null,
    selectedFileB64: null,
    certificates: [],
    reconnectTimer: null,
    reconnectAttempts: 0,
    checkingConnection: false,
};

// UI Elements
const DOM = {
    logConsole: document.getElementById('log-console'),
    statusText: document.getElementById('global-status-text'),
    statusIndicator: document.querySelector('.status-indicator'),
    restStatus: document.getElementById('rest-status'),
    tlsStatus: document.getElementById('tls-status'),
    btnReconnect: document.getElementById('btn-reconnect'),
    btnLaunchGUI: document.getElementById('btn-launch-gui'),
    themeToggle: document.getElementById('theme-toggle'),
    navLinks: document.querySelectorAll('.nav-links li'),
    views: document.querySelectorAll('.view'),
    pageTitle: document.getElementById('page-title'),
    
    // Certs
    btnRefreshCerts: document.getElementById('btn-refresh-certs'),
    certsTbody: document.getElementById('certs-tbody'),
    
    // Sign
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    fileDetails: document.getElementById('file-details'),
    fileName: document.getElementById('file-name'),
    fileSize: document.getElementById('file-size'),
    btnRemoveFile: document.getElementById('btn-remove-file'),
    btnExecuteSign: document.getElementById('btn-execute-sign'),
    signFormat: document.getElementById('sign-format'),
    addVisibleSeal: document.getElementById('add-visible-seal'),
    
    // Modal
    resultModal: document.getElementById('sign-result-modal'),
    btnCloseModal: document.getElementById('btn-close-modal'),
    btnDownloadSigned: document.getElementById('btn-download-signed'),
    
    // Settings
    apiUrlInput: document.getElementById('api-url'),
    apiTokenInput: document.getElementById('api-token'),
    btnSaveSettings: document.getElementById('btn-save-settings'),
};

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    setupNavigation();
    setupDragAndDrop();
    setupEventListeners();
    
    log('Sistema', 'Inicializando consola Web de AutoFirma...', 'info');
    setManualConnectIdleState();
});

// --- Theme Management ---
function initTheme() {
    const savedTheme = localStorage.getItem('autofirma-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function updateThemeIcon(theme) {
    const icon = DOM.themeToggle.querySelector('i');
    if (theme === 'dark') {
        icon.className = 'fa-solid fa-sun';
    } else {
        icon.className = 'fa-solid fa-moon';
    }
}

DOM.themeToggle.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('autofirma-theme', newTheme);
    updateThemeIcon(newTheme);
});

// --- Navigation ---
function setupNavigation() {
    DOM.navLinks.forEach(link => {
        link.addEventListener('click', () => {
            const route = link.getAttribute('data-route');
            const title = link.querySelector('span').textContent;
            
            // Update active link
            DOM.navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            // Show view
            DOM.views.forEach(v => v.classList.remove('active'));
            document.getElementById(`view-${route}`).classList.add('active');
            
            DOM.pageTitle.textContent = title;
            
            // View specific actions
            if (route === 'certificates' && AppState.certificates.length === 0) {
                loadCertificates();
            }
        });
    });
}

// --- Utility Functions ---
function log(context, message, type = 'info') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const time = new Date().toLocaleTimeString();
    
    let icon = '';
    if (type === 'error') icon = '<i class="fa-solid fa-circle-xmark"></i>';
    if (type === 'success') icon = '<i class="fa-solid fa-circle-check"></i>';
    if (type === 'warn') icon = '<i class="fa-solid fa-triangle-exclamation"></i>';
    
    entry.innerHTML = `<span class="text-muted">[${time}]</span> <span style="font-weight:bold">[${context}]</span> ${icon} ${message}`;
    
    DOM.logConsole.appendChild(entry);
    DOM.logConsole.scrollTop = DOM.logConsole.scrollHeight;
}

document.getElementById('clear-log')?.addEventListener('click', () => {
    DOM.logConsole.innerHTML = '';
});

// --- API Communication ---
async function apiCall(endpoint, method = 'GET', body = null, opts = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (AppState.apiToken) {
        headers['Authorization'] = `Bearer ${AppState.apiToken}`;
    }

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 0;
    let timeoutId = null;
    if (timeoutMs > 0 && typeof AbortController !== 'undefined') {
        const controller = new AbortController();
        options.signal = controller.signal;
        timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    }

    try {
        const response = await fetch(`${AppState.apiUrl}${endpoint}`, options);
        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        if (error && error.name === 'AbortError') {
            throw new Error(`timeout (${timeoutMs} ms)`);
        }
        throw error;
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
    }
}

// --- Connection Diagnostics ---
async function checkConnection() {
    if (AppState.checkingConnection) {
        return;
    }
    AppState.checkingConnection = true;
    setConnectionState(null); // Loading state
    try {
        const health = await apiCall('/health', 'GET', null, { timeoutMs: 3000 });
        if (health && health.ok) {
            AppState.reconnectAttempts = 0;
            if (AppState.reconnectTimer) {
                clearTimeout(AppState.reconnectTimer);
                AppState.reconnectTimer = null;
            }
            setConnectionState(true);
            DOM.restStatus.innerHTML = `<i class="fa-solid fa-check"></i> Activo: ${health.version || 'v2026'}`;
            DOM.restStatus.className = 'status-good text-success';
            log('Conexión', `API REST detectada correctamente.`, 'success');
            
            // Also check TLS trust
            checkTLSTrust();
        } else {
            throw new Error("Respuesta de salud inválida");
        }
    } catch (e) {
        setConnectionState(false);
        DOM.restStatus.innerHTML = `<i class="fa-solid fa-xmark"></i> Sin conexión (${e.message})`;
        DOM.restStatus.className = 'status-error text-danger';
        DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> No aplicable`;
        DOM.tlsStatus.className = 'text-muted';
        log('Conexión', `No se pudo conectar a AutoFirma local: ${e.message}`, 'error');
        scheduleAutoReconnect();
    } finally {
        AppState.checkingConnection = false;
    }
}

function scheduleAutoReconnect() {
    // Modo manual: no reconectar automáticamente.
}

function setManualConnectIdleState() {
    AppState.connected = false;
    if (AppState.reconnectTimer) {
        clearTimeout(AppState.reconnectTimer);
        AppState.reconnectTimer = null;
    }
    AppState.reconnectAttempts = 0;
    DOM.statusText.textContent = "Desconectado";
    DOM.statusIndicator.classList.remove('connected');
    DOM.statusIndicator.style.background = 'var(--muted-color)';
    if (DOM.btnReconnect) {
        DOM.btnReconnect.innerHTML = `<i class="fa-solid fa-plug"></i> Conectar`;
    }
    if (DOM.restStatus) {
        DOM.restStatus.innerHTML = `<i class="fa-solid fa-plug-circle-xmark"></i> Desconectado (pulsa Conectar)`;
        DOM.restStatus.className = 'text-muted';
    }
    if (DOM.tlsStatus) {
        DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-plug-circle-xmark"></i> Desconectado`;
        DOM.tlsStatus.className = 'text-muted';
    }
    syncSignButtonState();
}

async function checkTLSTrust() {
    const panelUsesHTTP = window.location && window.location.protocol === 'http:';
    try {
        const tls = await apiCall('/tls/trust-status', 'GET', null, { timeoutMs: 5000 });
        const trusted = inferTLSTrusted(tls);
        if (panelUsesHTTP) {
            DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-circle-info"></i> Panel en HTTP local (TLS opcional para esta vista)`;
            DOM.tlsStatus.className = 'text-muted';
            log('Seguridad', 'La consola REST está abierta por HTTP local. La confianza TLS solo afecta a uso HTTPS/WSS.', 'info');
            return;
        }
        if (tls && tls.ok && trusted) {
            DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-shield-check"></i> Certificados confiados en sistema`;
            DOM.tlsStatus.className = 'text-success';
            log('Seguridad', 'La CA local TLS está instalada y confiada. Las llamadas WSS y HTTPS están listas.', 'success');
        } else {
            DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Pendiente de confianza HTTPS`;
            DOM.tlsStatus.className = 'text-danger';
            log('Seguridad', 'La CA local no está en el almacén. Debes instalarla manualmente o con AutoFirma', 'warn');
        }
    } catch (e) {
        if (panelUsesHTTP) {
            DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-circle-info"></i> Panel en HTTP local (comprobación TLS omitida)`;
            DOM.tlsStatus.className = 'text-muted';
            log('Seguridad', `Comprobación TLS omitida en panel HTTP local: ${e.message}`, 'info');
            return;
        }
        DOM.tlsStatus.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Error al verificar: ${e.message}`;
        log('Seguridad', `No se pudo verificar TLS: ${e.message}`, 'error');
    }
}

function inferTLSTrusted(tls) {
    if (!tls || !tls.ok) return false;
    if (typeof tls.trusted === 'boolean') return tls.trusted;
    const lines = Array.isArray(tls.lines) ? tls.lines : [];
    if (lines.length === 0) return false;
    const joined = lines.join('\n').toLowerCase();
    const hasMissing = joined.includes('falta') || joined.includes('no encontrada') || joined.includes('pendiente');
    const hasOk = joined.includes('nss ok') || joined.includes('sistema: ok') || joined.includes('confiad');
    return hasOk && !hasMissing;
}

function setConnectionState(isConnected) {
    if (isConnected === null) {
        AppState.connected = false;
        DOM.statusText.textContent = "Conectando...";
        if (DOM.btnReconnect) {
            DOM.btnReconnect.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Conectando...`;
        }
        DOM.statusIndicator.classList.remove('connected');
        DOM.statusIndicator.style.background = 'var(--muted-color)';
    } else if (isConnected) {
        AppState.connected = true;
        DOM.statusText.textContent = "Conectado al Motor";
        if (DOM.btnReconnect) {
            DOM.btnReconnect.innerHTML = `<i class="fa-solid fa-rotate-right"></i> Reconectar`;
        }
        DOM.statusIndicator.classList.add('connected');
        DOM.statusIndicator.style.background = '';
    } else {
        AppState.connected = false;
        DOM.statusText.textContent = "Desconectado";
        if (DOM.btnReconnect) {
            DOM.btnReconnect.innerHTML = `<i class="fa-solid fa-plug"></i> Conectar`;
        }
        DOM.statusIndicator.classList.remove('connected');
        DOM.statusIndicator.style.background = 'var(--danger-color)';
    }
    syncSignButtonState();
}

DOM.btnReconnect.addEventListener('click', () => {
    if (AppState.reconnectTimer) {
        clearTimeout(AppState.reconnectTimer);
        AppState.reconnectTimer = null;
    }
    AppState.reconnectAttempts = 0;
    log('Sistema', 'Forzando reconexión al motor...', 'info');
    checkConnection();
});

DOM.btnLaunchGUI?.addEventListener('click', async () => {
    try {
        const res = await apiCall('/desktop/open', 'POST', { frontend: 'qt' });
        log('Desktop', res?.message || 'GUI Qt lanzada', 'success');
    } catch (e) {
        log('Desktop', `No se pudo lanzar GUI Qt por REST (${e.message}). Intentando protocolo...`, 'warn');
        try {
            window.location.href = 'afirma://';
        } catch (_) {
            // noop
        }
    }
});

// --- Settings View ---
DOM.btnSaveSettings.addEventListener('click', () => {
    const url = DOM.apiUrlInput.value.trim();
    const token = DOM.apiTokenInput.value.trim();
    if (url) {
        AppState.apiUrl = url.replace(/\/$/, "");
        AppState.apiToken = token;
        log('Configuración', `Trazada a ${AppState.apiUrl}`, 'success');
        checkConnection();
    }
});

// --- Certificates View ---
async function loadCertificates() {
    DOM.certsTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted"><i class="fa-solid fa-circle-notch fa-spin"></i> Cargando certificados desde AutoFirma...</td></tr>`;
    try {
        const data = await apiCall('/certificados');
        if (data && data.certificates) {
            AppState.certificates = data.certificates;
            renderCertificates();
            log('Certificados', `Se cargaron ${data.certificates.length} certificados del almacén.`, 'success');
        }
    } catch (e) {
        DOM.certsTbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger"><i class="fa-solid fa-circle-exclamation"></i> Error al cargar: ${e.message}</td></tr>`;
        log('Certificados', `Error al obtener certificados: ${e.message}`, 'error');
    }
}

function renderCertificates() {
    if (AppState.certificates.length === 0) {
        DOM.certsTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No se detectaron certificados en el almacén del sistema.</td></tr>`;
        return;
    }

    let html = '';
    AppState.certificates.forEach(c => {
        let iconClass = "fa-solid fa-id-card";
        if (c.source && c.source.toLowerCase().includes("pkcs11") || c.source && c.source.toLowerCase().includes("smartcard")) {
            iconClass = "fa-solid fa-sim-card text-primary"; // Tarjeta inteligente
        }

        let subjectName = c.name || c.subjectName || "Desconocido";
        let parts = subjectName.split(", ");
        let cName = parts.find(p => p.startsWith("CN="))?.substring(3) || subjectName;

        let issuer = c.issuerName || "";
        let iName = issuer.split(", ").find(p => p.startsWith("CN="))?.substring(3) || issuer;

        html += `
            <tr>
                <td style="text-align:center"><i class="${iconClass}" style="font-size:24px"></i></td>
                <td><strong>${cName}</strong><br><small class="text-muted">${c.nickname || ''}</small></td>
                <td><small>${iName}</small></td>
                <td><small>${c.validTo || 'N/A'}</small></td>
                <td><code style="font-size:11px; background:var(--secondary-color); padding: 2px 4px; border-radius:4px">${c.id ? c.id.substring(0,16)+'...' : ''}</code></td>
            </tr>
        `;
    });
    DOM.certsTbody.innerHTML = html;
}

DOM.btnRefreshCerts.addEventListener('click', loadCertificates);

// --- Sign File View ---
function setupDragAndDrop() {
    // Hidden Input logic
    DOM.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) processFileSelection(e.target.files[0]);
    });

    // Drag events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        DOM.dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }

    ['dragenter', 'dragover'].forEach(eventName => {
        DOM.dropZone.addEventListener(eventName, () => DOM.dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        DOM.dropZone.addEventListener(eventName, () => DOM.dropZone.classList.remove('dragover'), false);
    });

    DOM.dropZone.addEventListener('drop', (e) => {
        let dt = e.dataTransfer;
        let files = dt.files;
        if (files.length > 0) processFileSelection(files[0]);
    }, false);
}

function processFileSelection(file) {
    if (!file) return;

    // Convert file size to KB/MB
    let size = (file.size / 1024).toFixed(2);
    let sizeStr = size > 1024 ? (size / 1024).toFixed(2) + ' MB' : size + ' KB';

    DOM.fileName.textContent = file.name;
    DOM.fileSize.textContent = sizeStr;

    // Set icon based on type
    const ext = file.name.split('.').pop().toLowerCase();
    const iconEl = document.querySelector('.file-type-icon');
    if (ext === 'pdf') { iconEl.className = 'fa-solid fa-file-pdf file-type-icon text-danger'; }
    else if (ext === 'xml' || ext === 'facturae') { iconEl.className = 'fa-solid fa-file-code file-type-icon text-primary'; }
    else { iconEl.className = 'fa-solid fa-file-lines file-type-icon text-muted'; }

    // Read to Base64
    const reader = new FileReader();
    reader.onload = (e) => {
        const base64String = e.target.result.split(',')[1];
        AppState.selectedFile = file;
        AppState.selectedFileB64 = base64String;
        
        DOM.dropZone.classList.add('hidden');
        DOM.fileDetails.classList.remove('hidden');
        syncSignButtonState();
        
        // Match extension with format if auto
        if (ext === 'pdf') DOM.signFormat.value = 'PAdES';
        else if (ext === 'xml') DOM.signFormat.value = 'XAdES';
        else DOM.signFormat.value = 'CAdES';
        
        log('Firma', `Archivo cargado: ${file.name} (${sizeStr})`, 'info');
    };
    reader.onerror = () => {
        log('Error', `Fallo al leer el archivo en memoria`, 'error');
    };
    reader.readAsDataURL(file);
}

DOM.btnRemoveFile.addEventListener('click', () => {
    AppState.selectedFile = null;
    AppState.selectedFileB64 = null;
    DOM.fileInput.value = "";
    DOM.dropZone.classList.remove('hidden');
    DOM.fileDetails.classList.add('hidden');
    syncSignButtonState();
});

function syncSignButtonState() {
    const hasFile = !!AppState.selectedFileB64;
    DOM.btnExecuteSign.disabled = !(AppState.connected && hasFile);
}

// Execute REST Sign
DOM.btnExecuteSign.addEventListener('click', async () => {
    if (!AppState.selectedFileB64 || !AppState.connected) {
        log('Firma', 'Servidor no conectado o archivo no cargado', 'error');
        return;
    }

    const format = DOM.signFormat.value;
    const isPDF = DOM.fileName.textContent.toLowerCase().endsWith('.pdf');
    const seal = DOM.addVisibleSeal.checked && DOM.signFormat.value === 'PAdES';

    DOM.btnExecuteSign.disabled = true;
    DOM.btnExecuteSign.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Solicitando firma a AutoFirma...`;
    
    log('Firma', `Llamando a Petición POST /firmar (Formato: ${format}). Aparecerá AutoFirma Desktop para el PIN.`, 'info');

    try {
        const reqPayload = {
            dataB64: AppState.selectedFileB64,
            format: format,
            compatibilidadEstricta: true, // Ensure PAdES basic rules as Java did
            devolverFirmaB64: true,
            guardarEnDisco: false
        };
        
        if (seal) {
            reqPayload.selloVisible = {
                page: 1, x: 50, y: 50, w: 100, h: 50, rotation: 0
            };
        }

        const signedRes = await apiCall('/firmar', 'POST', reqPayload);
        
        if (signedRes.ok && signedRes.signatureB64) {
            log('Firma', `El documento fue firmado exitosamente originando un B64 modificado.`, 'success');
            
            // Generate link to download
            const blob = b64toBlob(signedRes.signatureB64, getMimeTypeFromFormat(format, isPDF));
            const blobUrl = URL.createObjectURL(blob);
            
            let finalName = AppState.selectedFile.name;
            const extSeparatorIdx = finalName.lastIndexOf('.');
            if (extSeparatorIdx !== -1) {
                finalName = finalName.substring(0, extSeparatorIdx) + "_signed" + finalName.substring(extSeparatorIdx);
            } else {
                finalName += "_signed";
            }
            if (format === 'XAdES' && !finalName.toLowerCase().endsWith('.xml')) finalName += '.xml';
            if (format === 'CAdES' && !finalName.toLowerCase().endsWith('.csig')) finalName += '.csig';
            
            DOM.btnDownloadSigned.href = blobUrl;
            DOM.btnDownloadSigned.download = finalName;
            
            DOM.resultModal.classList.remove('hidden');
        } else {
            throw new Error("No se devolvió un buffer de firma válido.");
        }
    } catch (e) {
        log('Firma', `Error firmando el archivo: ${e.message}`, 'error');
        alert(`Error al firmar: ${e.message}\nRevisa que AutoFirma Desktop se haya ejecutado o no esté cancelado el diálogo.`);
    } finally {
        DOM.btnExecuteSign.disabled = false;
        DOM.btnExecuteSign.innerHTML = `<i class="fa-solid fa-signature"></i> Firmar Ahora`;
    }
});

DOM.btnCloseModal.addEventListener('click', () => {
    DOM.resultModal.classList.add('hidden');
});

function b64toBlob(b64Data, contentType='', sliceSize=512) {
    const byteCharacters = atob(b64Data);
    const byteArrays = [];
    for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
        const slice = byteCharacters.slice(offset, offset + sliceSize);
        const byteNumbers = new Array(slice.length);
        for (let i = 0; i < slice.length; i++) {
            byteNumbers[i] = slice.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        byteArrays.push(byteArray);
    }
    return new Blob(byteArrays, {type: contentType});
}

function getMimeTypeFromFormat(format, wasPDF) {
    if (format === 'PAdES' || wasPDF) return 'application/pdf';
    if (format === 'XAdES') return 'application/xml';
    if (format === 'CAdES') return 'application/pkcs7-signature';
    return 'application/octet-stream';
}
