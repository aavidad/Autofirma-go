// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

// Test script para probar el WebSocket de AutoFirma
// Ejecutar en la consola del navegador en https://www.sededgsfp.gob.es/es/Paginas/TestAutofirma.aspx

console.log('🔌 Conectando al servidor WebSocket de AutoFirma...');

const ws = new WebSocket('ws://localhost:63117');

ws.onopen = () => {
    console.log('✅ Conectado al servidor AutoFirma');

    // Test 1: Echo (health check)
    console.log('📤 Enviando echo test...');
    ws.send('echo=test');
};

ws.onmessage = (event) => {
    console.log('📥 Respuesta del servidor:', event.data);

    if (event.data === 'OK') {
        console.log('✅ Echo test exitoso!');

        // Test 2: Obtener la URI de firma de la página
        // Buscar el enlace afirma:// en la página
        const afirmaLinks = document.querySelectorAll('a[href^="afirma://"]');
        if (afirmaLinks.length > 0) {
            const afirmaUri = afirmaLinks[0].href;
            console.log('📤 Enviando petición de firma:', afirmaUri);
            ws.send(afirmaUri);
        } else {
            console.log('⚠️ No se encontró enlace afirma:// en la página');
            console.log('💡 Haz clic en "Firmar" primero para generar el enlace');
        }
    } else if (event.data.startsWith('ERR-')) {
        console.error('❌ Error del servidor:', event.data);
    } else {
        console.log('✅ Firma completada! Respuesta:', event.data);
    }
};

ws.onerror = (error) => {
    console.error('❌ Error de WebSocket:', error);
    console.log('💡 Asegúrate de que el servidor esté corriendo:');
    console.log('   ./dist/autofirma-desktop --server');
};

ws.onclose = () => {
    console.log('🔌 Conexión cerrada');
};

// Guardar referencia global para poder enviar mensajes manualmente
window.autoFirmaWS = ws;

console.log('💡 Para enviar una petición manualmente:');
console.log('   window.autoFirmaWS.send("afirma://sign?...")');
