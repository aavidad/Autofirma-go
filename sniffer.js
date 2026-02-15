// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

// ==UserScript==
// @name         AutoFirma Protocol Sniffer
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Intercepts afirma:// links to debug parameters
// @author       You
// @match        *://*/*
// @grant        none
// ==/UserScript==

(function () {
    'use strict';

    console.log("🕵️ AutoFirma Sniffer Loaded!");

    // Helper to log params
    function logAfirmaURI(uri, source) {
        if (uri && (uri.startsWith('afirma://') || uri.startsWith('miniapplet://'))) {
            console.group("🚀 AutoFirma Launch Detected (" + source + ")");
            console.log("Full URI:", uri);

            try {
                // Parse params
                const clean = uri.replace(/^.*?\?/, '');
                const params = new URLSearchParams(clean);
                const obj = {};
                for (const [key, value] of params.entries()) {
                    obj[key] = value;
                }
                console.table(obj);

                // Decode DAT if present
                if (obj.dat) {
                    console.log("DAT (Base64 decoded preview):", atob(obj.dat).substring(0, 100) + "...");
                }
            } catch (e) {
                console.error("Error parsing params:", e);
            }
            console.groupEnd();
        }
    }

    // 1. Hook window.location.assign
    const originalAssign = window.location.assign;
    window.location.assign = function (url) {
        logAfirmaURI(url, "window.location.assign");
        return originalAssign.apply(window.location, arguments);
    };

    // 2. Hook window.location.replace
    const originalReplace = window.location.replace;
    window.location.replace = function (url) {
        logAfirmaURI(url, "window.location.replace");
        return originalReplace.apply(window.location, arguments);
    };

    // 3. Hook window.open
    const originalOpen = window.open;
    window.open = function (url, target, features) {
        logAfirmaURI(url, "window.open");
        return originalOpen.apply(window, arguments);
    };

    // 4. Hook clicking on links
    document.addEventListener('click', function (e) {
        const link = e.target.closest('a');
        if (link && link.href) {
            logAfirmaURI(link.href, "click");
        }
    }, true);

    // 5. Hook MiniApplet specific (if available)
    // Many sites use 'MiniApplet.sign(...)' which generates the URL internally.
    // We can try to intercept the result if they use specific libraries.

    console.log("Waiting for protocol launch...");

})();
