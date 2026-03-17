# Implementation Plan: AutoFirma Web Client

## Overview
This document outlines the plan to build a complete, fully featured web application to interface with the AutoFirma Go native application. The web app will communicate with the local AutoFirma backend using its REST/WebSocket API, giving it access to all the core capabilities (signing, certificates, configuration) usually performed by the Qt/Qml user interface.

## Goals
1. Provide a modern, beautiful web interface utilizing HTML/CSS/JS (no heavy framework required, allowing it to be hosted statically in GitHub Pages or any static server).
2. Connect to the local AutoFirma REST API (`127.0.0.1:63118`) and WSS API.
3. Replace the basic `test-autofirma-wss.html` script with a complete suite.

## Features to Implement
- **Connection Diagnostics:** Check if AutoFirma is running locally and properly trusted (via the `/health` and `/tls/trust-status` REST endpoints).
- **Certificate Manager:** List available certificates in the user's keystore (calling `/certificados`).
- **File Signing (REST API):**
  - Allow the user to drag and drop a file (PDF, XML, etc.) or select it via an input.
  - Read the file as Base64 in JavaScript.
  - Send the Base64 file via a `POST /firmar` request to the local active AutoFirma instance.
  - Receive the signed Base64 back and decode it to let the user download the resulting signed file directly in the browser.
- **Protocol Signing (WSS):**
  - Allow invoking the standard `afirma://` protocol for compatibility testing.

## Plan Steps
1. **Scaffold the App Structure:** Create the main `index.html`, `style.css` (with premium dark/light themes and modern UI components), and `app.js` files inside a new `web` folder.
2. **Implement API Services in JS:** Write the network abstraction functions to talk to `https://127.0.0.1:63118`.
3. **Build the UI Layout:** Create the sidebar (for navigation between "Firmar", "Certificados" y "Diagnósticos") and a main content area.
4. **Implement File Handling:** Set up the HTML5 File API and `FileReader` to encode/decode Base64.
5. **Add into version control:** Put everything under version control so it represents a full, polished client ready for GitHub.

## Technical Considerations
- We recently added `datosB64` to the AutoFirma REST API (in step 268) so that external webs can send a file over the network without needing local filesystem paths. This web app will take advantage of this new feature.
- Bypassing CORS is possible because the AutoFirma backend already allows requests coming from specific origins. We may need to ensure our REST server CORS headers allow requests generated from standard `file://` or GitHub Pages contexts.
