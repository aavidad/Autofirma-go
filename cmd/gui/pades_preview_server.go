// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type padesSaveRequest struct {
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	W    float64 `json:"w"`
	H    float64 `json:"h"`
	Page uint32  `json:"page"`
}

func (ui *UI) openPadesPreviewInBrowser(filePath string) error {
	if err := ui.ensurePadesPreviewServer(); err != nil {
		return err
	}
	if _, err := os.Stat(filePath); err != nil {
		return err
	}
	if w, h, err := getFirstPDFPageSize(filePath); err == nil && w > 0 && h > 0 {
		ui.PDFPageWidthPt = w
		ui.PDFPageHeightPt = h
	}

	token := ui.newPreviewToken()
	ui.PadesPreviewMu.Lock()
	ui.PadesPreviewToken = token
	ui.PadesPreviewFile = filePath
	ui.PadesPreviewMu.Unlock()

	q := url.Values{}
	q.Set("token", token)
	q.Set("w", fmt.Sprintf("%.4f", ui.PDFPageWidthPt))
	q.Set("h", fmt.Sprintf("%.4f", ui.PDFPageHeightPt))
	previewURL := ui.PadesPreviewBaseURL + "/pades-preview?" + q.Encode()
	return openExternal(previewURL)
}

func (ui *UI) ensurePadesPreviewServer() error {
	var startErr error
	ui.PadesPreviewServerOnce.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			startErr = err
			return
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/pades-preview", ui.handlePadesPreviewPage)
		mux.HandleFunc("/pades-preview/pdf", ui.handlePadesPreviewPDF)
		mux.HandleFunc("/pades-preview/save", ui.handlePadesPreviewSave)

		httpServer := &http.Server{Handler: mux}
		ui.PadesPreviewBaseURL = "http://" + ln.Addr().String()
		go func() {
			_ = httpServer.Serve(ln)
		}()
	})

	if startErr != nil {
		return startErr
	}
	if strings.TrimSpace(ui.PadesPreviewBaseURL) == "" {
		return fmt.Errorf("no se pudo iniciar el visor local")
	}
	return nil
}

func (ui *UI) handlePadesPreviewPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if !ui.previewTokenValid(token) {
		http.Error(w, "token invalido", http.StatusUnauthorized)
		return
	}

	pageW := parseFloatOrDefault(r.URL.Query().Get("w"), 595.28)
	pageH := parseFloatOrDefault(r.URL.Query().Get("h"), 841.89)
	ratio := pageH / pageW
	if ratio <= 0 {
		ratio = 841.89 / 595.28
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, renderPadesPreviewHTML(token, ratio))
}

func (ui *UI) handlePadesPreviewPDF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if !ui.previewTokenValid(token) {
		http.Error(w, "token invalido", http.StatusUnauthorized)
		return
	}

	ui.PadesPreviewMu.RLock()
	filePath := ui.PadesPreviewFile
	ui.PadesPreviewMu.RUnlock()
	if filePath == "" {
		http.Error(w, "pdf no disponible", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	http.ServeFile(w, r, filePath)
}

func (ui *UI) handlePadesPreviewSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if !ui.previewTokenValid(token) {
		http.Error(w, "token invalido", http.StatusUnauthorized)
		return
	}

	var req padesSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "json invalido", http.StatusBadRequest)
		return
	}
	if req.Page == 0 {
		req.Page = 1
	}

	ui.PadesSealX = clamp01(req.X)
	ui.PadesSealY = clamp01(req.Y)
	ui.PadesSealW = clamp01(req.W)
	ui.PadesSealH = clamp01(req.H)
	ui.PadesSealPage = req.Page
	ui.StatusMsg = fmt.Sprintf("Área recibida del visor web: x=%.1f%% y=%.1f%% ancho=%.1f%% alto=%.1f%%", ui.PadesSealX*100, ui.PadesSealY*100, ui.PadesSealW*100, ui.PadesSealH*100)
	ui.Window.Invalidate()

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (ui *UI) previewTokenValid(token string) bool {
	ui.PadesPreviewMu.RLock()
	defer ui.PadesPreviewMu.RUnlock()
	return token != "" && token == ui.PadesPreviewToken
}

func (ui *UI) newPreviewToken() string {
	seed := time.Now().UnixNano()
	rnd := rand.New(rand.NewSource(seed))
	return fmt.Sprintf("%d_%d", seed, rnd.Int63())
}

func parseFloatOrDefault(raw string, def float64) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return v
}

func renderPadesPreviewHTML(token string, ratio float64) string {
	pdfURL := "/pades-preview/pdf?token=" + url.QueryEscape(token) + "#page=1&zoom=page-width&view=FitH&toolbar=0&navpanes=0&scrollbar=0"
	return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Visor de sello PAdES</title>
<style>
:root { --bg:#f5f7fb; --fg:#1f2937; --muted:#6b7280; --primary:#0b5fff; --card:#ffffff; }
* { box-sizing:border-box; }
body { margin:0; font-family: "Segoe UI", Tahoma, sans-serif; background:var(--bg); color:var(--fg); font-size: clamp(12px, 1.2vw, 16px); }
.wrap { max-width: 1100px; margin: 0 auto; padding: clamp(8px, 1.4vw, 16px); }
.toolbar { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }
.btn { border:0; border-radius:8px; padding: clamp(8px, 1.1vw, 10px) clamp(10px, 1.4vw, 14px); color:#fff; background:var(--primary); cursor:pointer; font-weight:600; font-size: clamp(11px, 1.05vw, 14px); }
.btn.secondary { background:#4b5563; }
.hint { color:var(--muted); font-size: clamp(10px, 0.95vw, 13px); line-height: 1.35; max-width: 100%; overflow-wrap: anywhere; }
.viewer { background:var(--card); border:1px solid #d1d5db; border-radius:10px; padding:8px; overflow:auto; height: calc(100vh - 160px); min-height: 360px; }
.page { position:relative; width:min(100%, 980px); margin:0 auto; aspect-ratio: 1 / ` + fmt.Sprintf("%.8f", ratio) + `; background:#eef2f7; border:1px solid #d1d5db; }
.pdfViewport { position:absolute; inset:2.5% 2.5% 2.5% 2.5%; background:#fff; border:1px solid #c7d2e0; overflow:hidden; }
.pdf { position:absolute; inset:0; width:100%; height:100%; }
.overlay { position:absolute; inset:0; cursor:crosshair; }
.rect { position:absolute; border:2px solid #0b5fff; background:rgba(11,95,255,.20); pointer-events:none; }
@media (max-width: 720px) {
  .toolbar { gap: 8px; }
  .btn { flex: 1 1 auto; }
  .hint { width: 100%; }
  .viewer { height: calc(100vh - 185px); min-height: 300px; }
}
</style>
</head>
<body>
<div class="wrap">
  <div class="toolbar">
    <button class="btn" id="saveBtn">Guardar área en AutoFirma</button>
    <button class="btn secondary" id="resetBtn">Restablecer</button>
    <span class="hint" id="info">Arrastra para dibujar el rectángulo del sello sobre la primera página.</span>
  </div>
  <div class="viewer">
    <div class="page" id="page">
      <div class="pdfViewport" id="pdfViewport">
        <embed class="pdf" src="` + pdfURL + `" type="application/pdf" />
        <div class="overlay" id="overlay"></div>
        <div class="rect" id="rect"></div>
      </div>
    </div>
  </div>
</div>
<script>
(() => {
  const overlay = document.getElementById('overlay');
  const pdfViewport = document.getElementById('pdfViewport');
  const rect = document.getElementById('rect');
  const info = document.getElementById('info');

  let start = null;
  let seal = {x:0.62,y:0.04,w:0.34,h:0.12,page:1};

  function clamp01(v){ return Math.max(0, Math.min(1, v)); }
  function pxToNorm(x,y){
    const r = overlay.getBoundingClientRect();
    const nx = clamp01((x-r.left)/r.width);
    const nyTop = clamp01((y-r.top)/r.height);
    return {x:nx, yBottom:1-nyTop};
  }
  function renderRect(){
    const r = pdfViewport.getBoundingClientRect();
    rect.style.left = (seal.x * r.width) + 'px';
    rect.style.width = (seal.w * r.width) + 'px';
    rect.style.top = ((1 - (seal.y + seal.h)) * r.height) + 'px';
    rect.style.height = (seal.h * r.height) + 'px';
    info.textContent = 'x=' + (seal.x*100).toFixed(1) + '% y=' + (seal.y*100).toFixed(1) + '% ancho=' + (seal.w*100).toFixed(1) + '% alto=' + (seal.h*100).toFixed(1) + '%';
  }

  overlay.addEventListener('pointerdown', (e) => {
    overlay.setPointerCapture(e.pointerId);
    start = pxToNorm(e.clientX, e.clientY);
  });
  overlay.addEventListener('pointermove', (e) => {
    if(!start) return;
    const cur = pxToNorm(e.clientX, e.clientY);
    const x0 = Math.min(start.x, cur.x);
    const x1 = Math.max(start.x, cur.x);
    const y0 = Math.min(start.yBottom, cur.yBottom);
    const y1 = Math.max(start.yBottom, cur.yBottom);
    seal.x = clamp01(x0);
    seal.y = clamp01(y0);
    seal.w = clamp01(Math.max(0.01, x1-x0));
    seal.h = clamp01(Math.max(0.01, y1-y0));
    renderRect();
  });
  overlay.addEventListener('pointerup', () => { start = null; });
  overlay.addEventListener('pointercancel', () => { start = null; });

  document.getElementById('resetBtn').addEventListener('click', () => {
    seal = {x:0.62,y:0.04,w:0.34,h:0.12,page:1};
    renderRect();
  });

  document.getElementById('saveBtn').addEventListener('click', async () => {
    const res = await fetch('/pades-preview/save?token=` + url.QueryEscape(token) + `', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(seal)
    });
    if(!res.ok){
      alert('No se pudo guardar el área en la app.');
      return;
    }
    info.textContent = 'Área guardada en AutoFirma. Cerrando visor...';
    setTimeout(() => {
      window.open('', '_self');
      window.close();
      info.textContent = 'Área guardada. Puedes cerrar esta pestaña manualmente.';
    }, 120);
  });

  window.addEventListener('resize', renderRect);
  renderRect();
})();
</script>
</body>
</html>`
}
