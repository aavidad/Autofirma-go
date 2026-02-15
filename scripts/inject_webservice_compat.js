// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

// Inyectar en consola del navegador sobre la sede que usa AutoScript.
// Fuerza el flujo "servidor intermedio" usando el host local HTTPS.
(function () {
  var base = "https://127.0.0.1:63117";
  var storage = base + "/afirma-signature-storage/StorageService";
  var retrieve = base + "/afirma-signature-retriever/RetrieveService";

  if (!window.AutoScript) {
    console.error("[compat] AutoScript no está cargado todavía.");
    return;
  }

  if (typeof window.AutoScript.setForceWSMode === "function") {
    window.AutoScript.setForceWSMode(true);
  }
  if (typeof window.AutoScript.setServlets === "function") {
    window.AutoScript.setServlets(storage, retrieve);
  }
  if (typeof window.AutoScript.cargarAppAfirma === "function") {
    window.AutoScript.cargarAppAfirma();
  }

  console.log("[compat] AutoScript redirigido a:");
  console.log("  StorageService:", storage);
  console.log("  RetrieveService:", retrieve);
})();
