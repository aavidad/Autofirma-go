// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

// Script para interceptar AutoFirma y usar WebSocket
// Copiar y pegar en la consola de https://www.sededgsfp.gob.es/es/Paginas/TestAutofirma.aspx

console.log('🔧 Iniciando interceptor de AutoFirma...');

// Conectar al WebSocket
let ws = null;

function connectWS() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log('✅ Ya conectado al WebSocket');
        return;
    }

    console.log('🔌 Conectando a wss://127.0.0.1:63117/...');
    ws = new WebSocket('wss://127.0.0.1:63117/');

    ws.onopen = () => {
        console.log('✅ Conectado al servidor WSS de AutoFirma');
        console.log('💡 Ahora haz clic en "Firmar"');
    };

    ws.onmessage = (event) => {
        console.log('📥 Respuesta del servidor:', event.data);
        if (event.data === 'OK') {
            console.log('✅ ¡FIRMA COMPLETADA EXITOSAMENTE!');
            alert('✅ Firma completada con éxito');
        } else if (event.data.startsWith('ERR-')) {
            console.error('❌ Error:', event.data);
            alert('❌ Error: ' + event.data);
        }
    };

    ws.onerror = (error) => {
        console.error('❌ Error de WebSocket');
        console.log('💡 Solución: Abre https://127.0.0.1:63117/ y acepta el certificado');
    };

    ws.onclose = () => {
        console.log('🔌 Conexión cerrada');
    };
}

// Interceptar TODOS los clics en enlaces afirma://
document.addEventListener('click', function (e) {
    // Buscar si el clic fue en un enlace afirma:// o dentro de uno
    let target = e.target;
    while (target && target !== document) {
        if (target.tagName === 'A' && target.href && target.href.startsWith('afirma://')) {
            e.preventDefault();
            e.stopPropagation();

            const uri = target.href;
            console.log('🚫 Interceptado enlace afirma://');
            console.log('📋 URI:', uri.substring(0, 100) + '...');

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                console.error('❌ WebSocket no conectado. Conectando...');
                connectWS();
                setTimeout(() => {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        console.log('📤 Enviando petición por WebSocket...');
                        ws.send(uri);
                    }
                }, 1000);
            } else {
                console.log('📤 Enviando petición por WebSocket...');
                ws.send(uri);
            }

            return false;
        }
        target = target.parentElement;
    }
}, true); // Usar capture para interceptar antes

// Conectar automáticamente
connectWS();

console.log('✅ Interceptor activado');
console.log('💡 Haz clic en "Firmar" para probar');
