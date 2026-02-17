// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"autofirma-host/pkg/applog"
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"autofirma-host/pkg/updater"
	"autofirma-host/pkg/version"
	"bufio"
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync" // Added for WaitGroup
	"time"

	"github.com/digitorus/pdf"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

//go:embed logo.png
var embeddedHeaderLogo []byte

type SignatureResult struct {
	SignatureB64 string
	CertDER      []byte
}

type UI struct {
	Theme  *material.Theme
	Window *app.Window

	// State for widgets
	BtnSign         widget.Clickable
	BtnVerify       widget.Clickable
	BtnCheckCerts   widget.Clickable
	BtnBrowse       widget.Clickable
	BtnView         widget.Clickable // View current file
	BtnOpen         widget.Clickable // Open Signed PDF
	BtnOpenFolder   widget.Clickable // Open Containing Folder
	BtnValide       widget.Clickable // Open Valide URL
	BtnSignProtocol widget.Clickable // Sign button for protocol mode

	BtnModeSign   widget.Clickable
	BtnModeVerify widget.Clickable

	BtnAbout        widget.Clickable
	BtnCheckUpdates widget.Clickable
	BtnViewLogs     widget.Clickable
	BtnHealthCheck  widget.Clickable
	BtnFindIssue    widget.Clickable
	BtnCopyReport   widget.Clickable
	BtnOpenSealWeb  widget.Clickable
	ShowAbout       bool
	ChkVisibleSeal  widget.Bool
	ChkStrictCompat widget.Bool

	ListCerts    widget.List
	Certs        []protocol.Certificate
	SelectedCert int                // Index of selected cert, -1 if none
	CertClicks   []widget.Clickable // Clickable for each list item

	InputFile widget.Editor

	StatusMsg  string
	SignedFile string // Path to the last signed file

	IsSigning bool
	Mode      int // 0: Sign, 1: Verify

	PendingCadesConfirm bool
	PendingCadesFile    string
	PendingCadesCertID  string
	UpdateStatus        string
	UpdateLatestVersion string
	UpdateDownloadURL   string
	UpdateCheckRunning  bool
	HealthStatus        string
	HealthCheckRunning  bool
	ProblemScanRunning  bool

	DiagTransport      string
	DiagAction         string
	DiagSessionID      string
	DiagFormat         string
	DiagLastResult     string
	DiagLastUpdateTime string

	Protocol *ProtocolState // Web protocol state

	// PAdES visual seal placement (normalized in [0..1], y from bottom).
	PadesSealX     float64
	PadesSealY     float64
	PadesSealW     float64
	PadesSealH     float64
	PadesSealPage  uint32
	MainScrollList widget.List

	PDFPageWidthPt  float64
	PDFPageHeightPt float64

	PadesPreviewServerOnce sync.Once
	PadesPreviewBaseURL    string
	PadesPreviewMu         sync.RWMutex
	PadesPreviewToken      string
	PadesPreviewFile       string

	HeaderLogo image.Image
	BgLogo     image.Image

	// Background task coordination
	PendingWork sync.WaitGroup
	ShouldClose bool

	// WebSocket interaction
	SignatureDone chan SignatureResult // Sends the results when done
	IsServerMode  bool                 // True if launched via afirma://websocket or --server
}

func NewUI(w *app.Window) *UI {
	ui := &UI{
		Theme:           material.NewTheme(),
		Window:          w,
		SelectedCert:    -1,
		Mode:            0,
		PadesSealX:      0.62,
		PadesSealY:      0.04,
		PadesSealW:      0.34,
		PadesSealH:      0.12,
		PadesSealPage:   1,
		PDFPageWidthPt:  595.28,
		PDFPageHeightPt: 841.89,
		SignatureDone:   make(chan SignatureResult, 1),
		IsServerMode:    false, // Default
	}

	ui.ListCerts.Axis = layout.Vertical
	ui.InputFile.SingleLine = true
	ui.InputFile.Submit = true
	ui.MainScrollList.Axis = layout.Vertical
	if len(embeddedHeaderLogo) > 0 {
		if img, err := png.Decode(bytes.NewReader(embeddedHeaderLogo)); err == nil {
			ui.HeaderLogo = img
			ui.BgLogo = toWatermark(img, 22)
		}
	}

	// Load certificates in background
	go ui.loadCertificates()
	if shouldRunAutoUpdateCheck() {
		go ui.checkUpdates(true)
	} else {
		log.Printf("[Update] Auto-check omitido en modo servidor/websocket")
	}

	return ui
}

func shouldRunAutoUpdateCheck() bool {
	if serverModeFlag != nil && *serverModeFlag {
		return false
	}
	for i := 1; i < len(os.Args); i++ {
		arg := strings.ToLower(strings.Trim(os.Args[i], "\"'"))
		if strings.HasPrefix(arg, "afirma://websocket") {
			return false
		}
	}
	return true
}

func (ui *UI) browseFile() {
	title := "Seleccionar PDF para firmar"
	if ui.Mode == 1 {
		title = "Seleccionar PDF para verificar"
	}

	path, err := pickPDFPath(title)
	if err != nil {
		if runtime.GOOS == "windows" {
			ui.StatusMsg = "Error: No se pudo abrir el dialogo de archivo en Windows: " + err.Error()
		} else {
			ui.StatusMsg = "Error: No se pudo abrir el dialogo de archivo (instale zenity o kdialog)"
		}
		ui.Window.Invalidate()
		return
	}

	if path != "" {
		ui.InputFile.SetText(path)
		ui.Window.Invalidate()
	}
}

func (ui *UI) loadCertificates() {
	certs, err := certstore.GetSystemCertificates()
	if err != nil {
		ui.StatusMsg = "Error cargando certificados: " + err.Error()
		ui.Window.Invalidate()
		return
	}
	ui.Certs = certs
	ui.CertClicks = make([]widget.Clickable, len(certs))
	ui.Window.Invalidate()
}

func (ui *UI) openFile() {
	path := strings.TrimSpace(ui.SignedFile)
	if path == "" {
		ui.StatusMsg = "No hay PDF firmado para abrir."
		ui.Window.Invalidate()
		return
	}
	if err := openExternal(path); err != nil {
		ui.StatusMsg = "No se pudo abrir el PDF firmado: " + err.Error()
		ui.Window.Invalidate()
	}
}

func (ui *UI) openFolder() {
	path := strings.TrimSpace(ui.SignedFile)
	if path == "" {
		ui.StatusMsg = "No hay PDF firmado para localizar."
		ui.Window.Invalidate()
		return
	}
	if err := openContainingFolder(path); err != nil {
		ui.StatusMsg = "No se pudo abrir la carpeta del PDF firmado: " + err.Error()
		ui.Window.Invalidate()
	}
}

func (ui *UI) Layout(gtx layout.Context) layout.Dimensions {
	// SPECIAL MINIMALIST LAYOUT FOR PROTOCOL MODE OR SERVER MODE
	if ui.Protocol != nil || ui.IsServerMode {
		return layout.Stack{}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				paint.Fill(gtx.Ops, color.NRGBA{R: 245, G: 245, B: 245, A: 255})
				return layout.Dimensions{Size: gtx.Constraints.Min}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(24)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						// Title
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return material.H5(ui.Theme, "Solicitud de Firma").Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx)
						}),
						// Instruction
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							msg := "El sitio web solicita firmar un documento."
							if ui.InputFile.Text() != "" {
								msg = fmt.Sprintf("Documento listo: %s", filepath.Base(ui.InputFile.Text()))
							}
							return material.Body1(ui.Theme, msg).Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx)
						}),
						// File selector if empty (for local file flows)
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if ui.InputFile.Text() != "" {
								return layout.Dimensions{}
							}
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body2(ui.Theme, "No se ha descargado ningún documento automáticamente. Seleccione el archivo a firmar:")
									lbl.Color = color.NRGBA{R: 100, G: 100, B: 100, A: 255}
									return lbl.Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if ui.BtnBrowse.Clicked(gtx) {
										go ui.browseFile()
									}
									return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										btn := material.Button(ui.Theme, &ui.BtnBrowse, "Examinar archivo local...")
										btn.Background = color.NRGBA{R: 0, G: 120, B: 180, A: 255}
										return btn.Layout(gtx)
									})
								}),
							)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
						}),
						// Certificate List
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return material.List(ui.Theme, &ui.ListCerts).Layout(gtx, len(ui.Certs), func(gtx layout.Context, index int) layout.Dimensions {
								if ui.CertClicks[index].Clicked(gtx) {
									if !ui.Certs[index].CanSign {
										issue := strings.TrimSpace(ui.Certs[index].SignIssue)
										if issue == "" {
											issue = "certificado no apto para firma"
										}
										ui.StatusMsg = "Error: " + issue
										ui.Window.Invalidate()
										return layout.Dimensions{}
									}
									ui.SelectedCert = index
									ui.Window.Invalidate()
								}

								label := certificateDisplayLabel(ui.Certs[index])
								// Simple card style for certs
								btn := material.Button(ui.Theme, &ui.CertClicks[index], label)
								if ui.SelectedCert == index {
									// Highlight selected
									btn.Background = color.NRGBA{R: 0, G: 120, B: 180, A: 255}
									btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
								} else if ui.Certs[index].CanSign {
									btn.Background = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
									btn.Color = color.NRGBA{A: 255}
								} else {
									btn.Background = color.NRGBA{R: 245, G: 230, B: 230, A: 255}
									btn.Color = color.NRGBA{R: 100, G: 100, B: 100, A: 255}
								}
								btn.Inset = layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}

								return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return btn.Layout(gtx)
								})
							})
						}),
						// Visible Seal Checkbox (only if PAdES)
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								isPades := false
								if ui.Protocol != nil {
									isPades = normalizeProtocolFormat(ui.Protocol.SignFormat) == "pades" || normalizeProtocolFormat(ui.Protocol.Params.Get("format")) == "pades"
								}
							if !isPades {
								return layout.Dimensions{}
							}
							return material.CheckBox(ui.Theme, &ui.ChkVisibleSeal, "Añadir sello visible al PDF").Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return ui.layoutSessionDiagnostics(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if strings.TrimSpace(ui.DiagAction) == "" && strings.TrimSpace(ui.DiagLastResult) == "" {
								return layout.Dimensions{}
							}
							return layout.Spacer{Height: unit.Dp(10)}.Layout(gtx)
						}),
						// Status/Spinner/Sign Button
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if ui.IsSigning {
								return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Max.X = gtx.Dp(24)
										gtx.Constraints.Max.Y = gtx.Dp(24)
										return material.Loader(ui.Theme).Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return material.Body2(ui.Theme, "Firmando documento...").Layout(gtx)
									}),
								)
							}

							if ui.BtnSignProtocol.Clicked(gtx) {
								if ui.SelectedCert >= 0 {
									go ui.signCurrentFile()
								}
							}

							btn := material.Button(ui.Theme, &ui.BtnSignProtocol, "Firmar documento")
							if ui.SelectedCert < 0 || ui.InputFile.Text() == "" {
								btn.Background = color.NRGBA{R: 200, G: 200, B: 200, A: 255}
							} else {
								btn.Background = color.NRGBA{R: 0, G: 150, B: 0, A: 255}
							}
							return btn.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if ui.StatusMsg != "" {
								return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									msg := material.Body2(ui.Theme, ui.StatusMsg)
									// Make it clear if it's an error
									if strings.Contains(strings.ToLower(ui.StatusMsg), "error") {
										msg.Color = color.NRGBA{R: 200, G: 0, B: 0, A: 255}
									}
									return msg.Layout(gtx)
								})
							}
							return layout.Dimensions{}
						}),
					)
				})
			}),
		)
	}

	// NORMAL LAYOUT
	return layout.Stack{}.Layout(gtx,
		// Solid White Background
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.Fill(gtx.Ops, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
			if ui.BgLogo != nil {
				b := ui.BgLogo.Bounds()
				if b.Dx() > 0 && b.Dy() > 0 {
					maxW := (gtx.Constraints.Max.X * 72) / 100
					if maxW < 1 {
						maxW = 1
					}
					h := int(float64(maxW) * float64(b.Dy()) / float64(b.Dx()))
					maxH := (gtx.Constraints.Max.Y * 60) / 100
					if h > maxH && maxH > 0 {
						h = maxH
						maxW = int(float64(h) * float64(b.Dx()) / float64(b.Dy()))
					}
					if h < 1 {
						h = 1
					}
					if maxW < 1 {
						maxW = 1
					}
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min = image.Pt(maxW, h)
						gtx.Constraints.Max = gtx.Constraints.Min
						bg := widget.Image{
							Src:      paint.NewImageOp(ui.BgLogo),
							Fit:      widget.Contain,
							Position: layout.Center,
						}
						return bg.Layout(gtx)
					})
				}
			}
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),

		// Content Layer
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return material.List(ui.Theme, &ui.MainScrollList).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
				return layout.Flex{
					Axis: layout.Vertical,
				}.Layout(gtx,
					// Header (Title Only)
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if ui.HeaderLogo == nil {
										return layout.Dimensions{}
									}
									b := ui.HeaderLogo.Bounds()
									targetH := gtx.Dp(unit.Dp(34))
									if targetH < 1 {
										targetH = 1
									}
									targetW := targetH * 3
									if b.Dx() > 0 && b.Dy() > 0 {
										targetW = int(float64(targetH) * float64(b.Dx()) / float64(b.Dy()))
									}
									gtx.Constraints.Min = image.Pt(targetW, targetH)
									gtx.Constraints.Max = gtx.Constraints.Min
									img := widget.Image{
										Src:      paint.NewImageOp(ui.HeaderLogo),
										Fit:      widget.Contain,
										Position: layout.W,
									}
									return img.Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Spacer{Width: unit.Dp(10)}.Layout(gtx)
								}),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return material.H3(ui.Theme, "Autofirma Dipgra").Layout(gtx)
								}),
							)
						})
					}),

					// Mode Switcher
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									if ui.BtnModeSign.Clicked(gtx) {
										ui.Mode = 0
										ui.StatusMsg = ""
										ui.Window.Invalidate()
									}
									btn := material.Button(ui.Theme, &ui.BtnModeSign, "Firmar Documento")
									if ui.Mode == 0 {
										btn.Background = color.NRGBA{R: 63, G: 81, B: 181, A: 255} // Active Blue
									} else {
										btn.Background = color.NRGBA{R: 200, G: 200, B: 200, A: 255} // Inactive Grey
									}
									return btn.Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
								}),
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									if ui.BtnModeVerify.Clicked(gtx) {
										ui.Mode = 1
										ui.StatusMsg = ""
										if ui.SignedFile != "" {
											ui.InputFile.SetText(ui.SignedFile)
										}
										ui.Window.Invalidate()
									}
									btn := material.Button(ui.Theme, &ui.BtnModeVerify, "Verificar Firma")
									if ui.Mode == 1 {
										btn.Background = color.NRGBA{R: 63, G: 81, B: 181, A: 255} // Active Blue
									} else {
										btn.Background = color.NRGBA{R: 200, G: 200, B: 200, A: 255} // Inactive Grey
									}
									return btn.Layout(gtx)
								}),
							)
						})
					}),

					// File Input
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									label := "Ruta del fichero PDF para firmar:"
									if ui.Mode == 1 {
										label = "Ruta del fichero PDF para verificar:"
									}
									return material.H6(ui.Theme, label).Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
											ed := material.Editor(ui.Theme, &ui.InputFile, "Introduzca la ruta completa del PDF...")
											ed.Editor.Submit = true
											return ed.Layout(gtx)
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											if ui.BtnBrowse.Clicked(gtx) {
												go ui.browseFile()
											}

											browse := material.Button(ui.Theme, &ui.BtnBrowse, "Examinar...")

											// View Button
											if ui.BtnView.Clicked(gtx) {
												path := ui.InputFile.Text()
												if path != "" {
													go func() { _ = openExternal(path) }()
												}
											}
											viewBtn := material.Button(ui.Theme, &ui.BtnView, "Ver")
											if ui.InputFile.Text() == "" {
												viewBtn.Background = color.NRGBA{R: 200, G: 200, B: 200, A: 255}
											} else {
												viewBtn.Background = color.NRGBA{R: 0, G: 150, B: 200, A: 255} // Blueish
											}

											return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														return viewBtn.Layout(gtx)
													})
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														return browse.Layout(gtx)
													})
												}),
											)
										}),
									)
								}),
							)
						})
					}),

					// PAdES visual seal preview/drawing (desktop sign mode only).
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if ui.Mode != 0 || ui.Protocol != nil {
							return layout.Dimensions{}
						}
						return ui.layoutPadesSealEditor(gtx)
					}),

					// Certificate List Header (Only in Sign Mode)
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if ui.Mode == 0 {
							return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return material.H6(ui.Theme, "Seleccionar Certificado:").Layout(gtx)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if ui.BtnCheckCerts.Clicked(gtx) {
											ui.checkCertificates()
										}
										btn := material.Button(ui.Theme, &ui.BtnCheckCerts, "Comprobar certificados")
										btn.Background = color.NRGBA{R: 80, G: 80, B: 80, A: 255}
										return btn.Layout(gtx)
									}),
								)
							})
						}
						return layout.Dimensions{}
					}),

					// Certificate List (Only in Sign Mode)
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if ui.Mode != 0 {
							return layout.Dimensions{}
						}
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Stack{}.Layout(gtx,
								layout.Expanded(func(gtx layout.Context) layout.Dimensions {
									// Card-like container for better contrast and separation.
									panelH := gtx.Dp(unit.Dp(220))
									if panelH < 160 {
										panelH = 160
									}
									gtx.Constraints.Min.Y = panelH
									gtx.Constraints.Max.Y = panelH

									paint.FillShape(
										gtx.Ops,
										color.NRGBA{R: 248, G: 250, B: 252, A: 255},
										clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, panelH)}.Op(),
									)
									paint.FillShape(gtx.Ops, color.NRGBA{R: 190, G: 198, B: 210, A: 255}, clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, 1)}.Op())
									paint.FillShape(gtx.Ops, color.NRGBA{R: 190, G: 198, B: 210, A: 255}, clip.Rect{Min: image.Pt(0, panelH-1), Max: image.Pt(gtx.Constraints.Max.X, panelH)}.Op())
									paint.FillShape(gtx.Ops, color.NRGBA{R: 190, G: 198, B: 210, A: 255}, clip.Rect{Max: image.Pt(1, panelH)}.Op())
									paint.FillShape(gtx.Ops, color.NRGBA{R: 190, G: 198, B: 210, A: 255}, clip.Rect{Min: image.Pt(gtx.Constraints.Max.X-1, 0), Max: image.Pt(gtx.Constraints.Max.X, panelH)}.Op())
									return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, panelH)}
								}),
								layout.Stacked(func(gtx layout.Context) layout.Dimensions {
									panelH := gtx.Dp(unit.Dp(220))
									if panelH < 160 {
										panelH = 160
									}
									gtx.Constraints.Min.Y = panelH
									gtx.Constraints.Max.Y = panelH
									return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return material.List(ui.Theme, &ui.ListCerts).Layout(gtx, len(ui.Certs), func(gtx layout.Context, index int) layout.Dimensions {
											if ui.CertClicks[index].Clicked(gtx) {
												if !ui.Certs[index].CanSign {
													issue := strings.TrimSpace(ui.Certs[index].SignIssue)
													if issue == "" {
														issue = "certificado no apto para firma"
													}
													ui.StatusMsg = "Error: " + issue
													ui.Window.Invalidate()
													return layout.Dimensions{}
												}
												ui.SelectedCert = index
												if ui.Protocol != nil {
													ui.signCurrentFile()
												}
												ui.Window.Invalidate()
											}

											label := certificateDisplayLabel(ui.Certs[index])
											item := material.Button(ui.Theme, &ui.CertClicks[index], label)
											if ui.Certs[index].CanSign {
												item.Background = color.NRGBA{R: 235, G: 243, B: 251, A: 255}
											} else {
												item.Background = color.NRGBA{R: 248, G: 226, B: 226, A: 255}
											}
											item.Color = color.NRGBA{R: 20, G: 20, B: 20, A: 255}
											if index == ui.SelectedCert {
												item.Background = color.NRGBA{R: 178, G: 210, B: 246, A: 255}
											}

											return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return item.Layout(gtx)
											})
										})
									})
								}),
							)
						})
					}),

	// Status
	layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		if ui.StatusMsg != "" {
							return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return material.Body2(ui.Theme, ui.StatusMsg).Layout(gtx)
							})
						}
						return layout.Dimensions{}
	}),

					// Session diagnostics
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return ui.layoutSessionDiagnostics(gtx)
					}),

					// Action Buttons
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								// Sign/Verify Button
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if ui.IsSigning {
										return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return material.Loader(ui.Theme).Layout(gtx)
										})
									}

									if ui.Mode == 0 {
										// Sign Mode
										if ui.BtnSign.Clicked(gtx) {
											ui.signCurrentFile()
										}

										btn := material.Button(ui.Theme, &ui.BtnSign, "Firmar PDF")
										if ui.SelectedCert == -1 || ui.InputFile.Text() == "" {
											btn.Background = color.NRGBA{R: 200, G: 200, B: 200, A: 255} // Disabled look
										}
										return btn.Layout(gtx)

									} else {
										// Verify Mode
										if ui.BtnVerify.Clicked(gtx) {
											ui.verifyCurrentFile()
										}
										btn := material.Button(ui.Theme, &ui.BtnVerify, "Verificar Firma")
										if ui.InputFile.Text() == "" {
											btn.Background = color.NRGBA{R: 200, G: 200, B: 200, A: 255} // Disabled look
										}

										// Add ValidE button below
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return btn.Layout(gtx)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												if ui.BtnValide.Clicked(gtx) {
													_ = openExternal("https://valide.redsara.es/valide/validarFirma/ejecutar.html")
												}
												valideBtn := material.Button(ui.Theme, &ui.BtnValide, "Validación Oficial (Valide)")
												valideBtn.Background = color.NRGBA{R: 200, G: 0, B: 0, A: 255} // Dark Red
												return valideBtn.Layout(gtx)
											}),
										)
									}
								}),

								// Open Buttons (Only if signed file exists and in Sign Mode)
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if ui.SignedFile == "" || ui.Mode == 1 {
										return layout.Dimensions{}
									}

									return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												if ui.BtnOpen.Clicked(gtx) {
													ui.openFile()
												}
												b := material.Button(ui.Theme, &ui.BtnOpen, "Abrir PDF Firmado")
												b.Background = color.NRGBA{R: 50, G: 150, B: 50, A: 255} // Green
												return b.Layout(gtx)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} })
											}),
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												if ui.BtnOpenFolder.Clicked(gtx) {
													ui.openFolder()
												}
												b := material.Button(ui.Theme, &ui.BtnOpenFolder, "Abrir Carpeta")
												b.Background = color.NRGBA{R: 100, G: 100, B: 100, A: 255} // Grey
												return b.Layout(gtx)
											}),
										)
									})
								}),
							)
						})
					}),

					// Footer / About
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							if ui.BtnAbout.Clicked(gtx) {
								ui.ShowAbout = !ui.ShowAbout
								ui.Window.Invalidate()
							}

							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return material.Button(ui.Theme, &ui.BtnAbout, "Acerca de").Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if ui.ShowAbout {
										return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return material.Body2(ui.Theme, "Version: "+version.CurrentVersion).Layout(gtx)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return material.Body2(ui.Theme, "Creado por Alberto Avidad Fernández de la Oficina de Software Libre de la Diputación de Granada").Layout(gtx)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													if ui.BtnCheckUpdates.Clicked(gtx) && !ui.UpdateCheckRunning {
														go ui.checkUpdates(false)
													}
													btnText := "Buscar actualizaciones"
													if ui.UpdateCheckRunning {
														btnText = "Comprobando actualizaciones..."
													}
													btn := material.Button(ui.Theme, &ui.BtnCheckUpdates, btnText)
													if ui.UpdateCheckRunning {
														btn.Background = color.NRGBA{R: 150, G: 150, B: 150, A: 255}
													}
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													if ui.BtnViewLogs.Clicked(gtx) {
														logPath := resolveLogDirectory()
														_ = os.MkdirAll(logPath, 0755)
														if err := openExternal(logPath); err != nil {
															ui.UpdateStatus = "No se pudo abrir la carpeta de logs: " + err.Error()
														}
													}
													btn := material.Button(ui.Theme, &ui.BtnViewLogs, "Ver logs")
													btn.Background = color.NRGBA{R: 70, G: 70, B: 70, A: 255}
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													if ui.BtnHealthCheck.Clicked(gtx) && !ui.HealthCheckRunning {
														go ui.runLocalHealthCheck()
													}
													btnText := "Chequeo local"
													if ui.HealthCheckRunning {
														btnText = "Chequeo en curso..."
													}
													btn := material.Button(ui.Theme, &ui.BtnHealthCheck, btnText)
													btn.Background = color.NRGBA{R: 90, G: 90, B: 140, A: 255}
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													if ui.BtnFindIssue.Clicked(gtx) && !ui.ProblemScanRunning {
														go ui.runProblemFinder()
													}
													btnText := "Encontrar problema"
													if ui.ProblemScanRunning {
														btnText = "Analizando problema..."
													}
													btn := material.Button(ui.Theme, &ui.BtnFindIssue, btnText)
													btn.Background = color.NRGBA{R: 140, G: 95, B: 40, A: 255}
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													if ui.BtnCopyReport.Clicked(gtx) {
														ui.copyTechnicalReport()
													}
													btn := material.Button(ui.Theme, &ui.BtnCopyReport, "Copiar reporte técnico")
													btn.Background = color.NRGBA{R: 80, G: 110, B: 80, A: 255}
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														return material.CheckBox(ui.Theme, &ui.ChkStrictCompat, "Modo compatibilidad estricta").Layout(gtx)
													})
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													msg := strings.TrimSpace(ui.UpdateStatus)
													if msg == "" {
														return layout.Dimensions{}
													}
													lbl := material.Body2(ui.Theme, msg)
													if strings.Contains(strings.ToLower(msg), "nueva version") {
														lbl.Color = color.NRGBA{R: 0, G: 110, B: 0, A: 255}
													}
													return lbl.Layout(gtx)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													msg := strings.TrimSpace(ui.HealthStatus)
													if msg == "" {
														return layout.Dimensions{}
													}
													lbl := material.Body2(ui.Theme, msg)
													return lbl.Layout(gtx)
												}),
											)
										})
									}
									return layout.Dimensions{}
								}),
							)
						})
					}),
				)
			})
		}),
	)
}

func (ui *UI) layoutPadesSealEditor(gtx layout.Context) layout.Dimensions {
	filePath := strings.TrimSpace(ui.InputFile.Text())
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.CheckBox(ui.Theme, &ui.ChkVisibleSeal, "Añadir sello visible en PAdES").Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if ui.ChkVisibleSeal.Value {
					return layout.Dimensions{}
				}
				msg := material.Caption(ui.Theme, "Desactivado: se firmará PAdES sin sello visible.")
				msg.Color = color.NRGBA{R: 90, G: 90, B: 90, A: 255}
				return msg.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value {
					return layout.Dimensions{}
				}
				return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value {
					return layout.Dimensions{}
				}
				if filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
					msg := material.Body2(ui.Theme, "Seleccione un PDF para previsualizar y dibujar el área de firma.")
					msg.Color = color.NRGBA{R: 90, G: 90, B: 90, A: 255}
					return msg.Layout(gtx)
				}
				return layout.Dimensions{}
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value || filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
					return layout.Dimensions{}
				}
				return material.H6(ui.Theme, "Posición del sello PAdES").Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value || filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
					return layout.Dimensions{}
				}
				info := fmt.Sprintf(
					"Página %d | x=%.1f%% y=%.1f%% ancho=%.1f%% alto=%.1f%%",
					ui.PadesSealPage,
					ui.PadesSealX*100,
					ui.PadesSealY*100,
					ui.PadesSealW*100,
					ui.PadesSealH*100,
				)
				return material.Body2(ui.Theme, info).Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value || filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
					return layout.Dimensions{}
				}
				if ui.BtnOpenSealWeb.Clicked(gtx) {
					if w, h, err := getFirstPDFPageSize(filePath); err == nil && w > 0 && h > 0 {
						ui.PDFPageWidthPt = w
						ui.PDFPageHeightPt = h
					}
					if err := ui.openPadesPreviewInBrowser(filePath); err != nil {
						ui.StatusMsg = "Error abriendo visor web: " + err.Error()
					} else {
						ui.StatusMsg = "Visor web abierto. Dibuja el sello y pulsa Guardar en el navegador."
					}
					ui.Window.Invalidate()
				}
				btn := material.Button(ui.Theme, &ui.BtnOpenSealWeb, "Abrir visor PDF en navegador")
				btn.Background = color.NRGBA{R: 30, G: 120, B: 170, A: 255}
				return btn.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value || filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
					return layout.Dimensions{}
				}
				msg := material.Caption(ui.Theme, "La selección del área se realiza solo desde el visor web.")
				return msg.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !ui.ChkVisibleSeal.Value || filePath == "" || !strings.EqualFold(filepath.Ext(filePath), ".pdf") {
					return layout.Dimensions{}
				}
				return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx)
			}),
		)
	})
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func getFirstPDFPageSize(filePath string) (float64, float64, error) {
	r, err := pdf.Open(filePath)
	if err != nil {
		return 0, 0, err
	}
	if r.NumPage() < 1 {
		return 0, 0, fmt.Errorf("el PDF no contiene páginas")
	}

	p := r.Page(1)
	box := inheritedPageBox(p.V, "CropBox")
	if box.IsNull() {
		box = inheritedPageBox(p.V, "MediaBox")
	}
	if box.IsNull() || box.Len() < 4 {
		return 0, 0, fmt.Errorf("no se pudo obtener MediaBox/CropBox de la página 1")
	}
	llx := box.Index(0).Float64()
	lly := box.Index(1).Float64()
	urx := box.Index(2).Float64()
	ury := box.Index(3).Float64()
	w := urx - llx
	h := ury - lly
	if w <= 0 || h <= 0 {
		return 0, 0, fmt.Errorf("dimensiones de página inválidas")
	}
	return w, h, nil
}

func inheritedPageBox(v pdf.Value, key string) pdf.Value {
	for !v.IsNull() {
		if box := v.Key(key); !box.IsNull() {
			return box
		}
		v = v.Key("Parent")
	}
	return pdf.Value{}
}

func (ui *UI) verifyCurrentFile() {
	filePath := ui.InputFile.Text()
	if filePath == "" {
		ui.StatusMsg = "Por favor, introduzca la ruta del PDF."
		ui.Window.Invalidate()
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		ui.StatusMsg = "Error leyendo el archivo: " + err.Error()
		ui.Window.Invalidate()
		return
	}

	dataB64 := base64.StdEncoding.EncodeToString(data)

	ui.StatusMsg = "Verificando..."
	ui.IsSigning = true
	ui.Window.Invalidate()

	go func() {
		var stopWait chan struct{}
		defer func() {
			if stopWait != nil {
				close(stopWait)
			}
			ui.IsSigning = false
			ui.Window.Invalidate()
		}()

		// Java-compatible active waiting: keep transaction alive while user signs.
		if ui.Protocol != nil && ui.Protocol.ActiveWaiting && ui.Protocol.STServlet != "" && ui.Protocol.RequestID != "" {
			log.Printf("[UI] Starting active WAIT loop (id=%s)", ui.Protocol.RequestID)
			stopWait = make(chan struct{})
			ui.PendingWork.Add(1)
			go func() {
				defer ui.PendingWork.Done()

				// Initial wait marker
				if err := ui.Protocol.SendWaitSignal(); err != nil {
					log.Printf("[UI] WAIT initial send failed: %v", err)
				}

				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-stopWait:
						return
					case <-ticker.C:
						if err := ui.Protocol.SendWaitSignal(); err != nil {
							log.Printf("[UI] WAIT periodic send failed: %v", err)
						}
					}
				}
			}()
		}

		result, err := signer.VerifyData(dataB64, "", "pades")
		if err != nil {
			ui.StatusMsg = "Error en la verificación: " + err.Error()
			return
		}

		if result.Valid {
			ui.StatusMsg = "✅ VÁLIDO\nFirmante: " + result.SignerName + "\nEmail: " + result.SignerEmail + "\nFecha: " + result.Timestamp
		} else {
			ui.StatusMsg = "❌ INVÁLIDO\nRazón: " + result.Reason
		}
		ui.Window.Invalidate()
	}()
}

func (ui *UI) checkCertificates() {
	if len(ui.Certs) == 0 {
		ui.StatusMsg = "No hay certificados cargados para comprobar."
		ui.Window.Invalidate()
		return
	}
	if ui.IsSigning {
		ui.StatusMsg = "Hay una operacion en curso. Espere para comprobar certificados."
		ui.Window.Invalidate()
		return
	}

	ui.IsSigning = true
	ui.StatusMsg = "Comprobando certificados (firma de prueba CAdES)..."
	ui.Window.Invalidate()

	ui.PendingWork.Add(1)
	go func() {
		defer ui.PendingWork.Done()
		defer func() {
			ui.IsSigning = false
			ui.Window.Invalidate()
		}()

		probeB64 := base64.StdEncoding.EncodeToString([]byte("autofirma-cert-check"))
		okCount := 0
		failCount := 0

		for i := range ui.Certs {
			sigB64, err := signer.SignData(probeB64, ui.Certs[i].ID, "", "cades", nil)
			if err != nil || strings.TrimSpace(sigB64) == "" {
				ui.Certs[i].CanSign = false
				ui.Certs[i].SignIssue = normalizeCheckIssue(err)
				failCount++
				continue
			}
			ui.Certs[i].CanSign = true
			ui.Certs[i].SignIssue = ""
			okCount++
		}

		ui.StatusMsg = fmt.Sprintf("Comprobacion finalizada. Aptos: %d, No aptos: %d", okCount, failCount)
		ui.Window.Invalidate()
	}()
}

func (ui *UI) signCurrentFile() {
	if ui.SelectedCert == -1 {
		ui.StatusMsg = "Por favor, seleccione un certificado."
		ui.Window.Invalidate()
		return
	}
	certID := ui.Certs[ui.SelectedCert].ID
	if !ui.Certs[ui.SelectedCert].CanSign {
		issue := strings.TrimSpace(ui.Certs[ui.SelectedCert].SignIssue)
		if issue == "" {
			issue = "certificado no apto para firma"
		}
		ui.StatusMsg = "Error: " + issue
		ui.Window.Invalidate()
		return
	}
	if ui.IsSigning {
		return
	}

	filePath := ui.InputFile.Text()
	if filePath == "" {
		ui.StatusMsg = "Por favor, introduzca la ruta del PDF."
		ui.Window.Invalidate()
		return
	}
	if _, err := os.Stat(filePath); err != nil {
		ui.StatusMsg = "Error: no se puede acceder al fichero seleccionado."
		ui.Window.Invalidate()
		return
	}

	// Sign
	ui.StatusMsg = "Iniciando proceso de firma..."
	ui.SignedFile = "" // Reset previous signed file
	ui.IsSigning = true
	ui.Window.Invalidate()

	// Run in background to not block UI
	ui.PendingWork.Add(1)
	go func() {
		defer func() {
			ui.IsSigning = false
			ui.Window.Invalidate()
		}()
		defer ui.PendingWork.Done()

		// 1. Read file inside goroutine
		data, err := os.ReadFile(filePath)
		if err != nil {
			ui.StatusMsg = "Error leyendo el archivo: " + err.Error()
			return
		}

		// 2. Convert to Base64
		dataB64 := base64.StdEncoding.EncodeToString(data)

		// 3. Determine format based on extension or protocol
		ext := strings.ToLower(filepath.Ext(filePath))
		format := "pades" // Default

		// If in protocol mode and format was specified, use that
		if ui.Protocol != nil && ui.Protocol.SignFormat != "" {
			format = normalizeProtocolFormat(ui.Protocol.SignFormat)
			log.Printf("[UI] Using protocol-specified format: %s", format)
		} else {
			// Auto-detect from extension
			if ext == ".xml" {
				format = "xades"
			} else if ext == ".csig" || ext == ".sig" {
				format = "cades"
			}
		}
		format = normalizeProtocolFormat(format)
		opAction := "sign"
		if ui.Protocol != nil {
			opAction = ui.Protocol.Action
		}
		if err := ui.validateSignPreconditions(filePath, format); err != nil {
			ui.StatusMsg = "Error: " + err.Error()
			ui.Window.Invalidate()
			return
		}
		ui.updateSessionDiagnostics("local-ui", opAction, getProtocolSessionID(ui.Protocol), format, "precondiciones_ok")

		// Handling of Windows re-prompt for CAdES if PAdES is non-exportable
		confirmingCades := runtime.GOOS == "windows" &&
			ui.Protocol == nil &&
			strings.EqualFold(format, "pades") &&
			ui.PendingCadesConfirm &&
			ui.PendingCadesFile == filePath &&
			ui.PendingCadesCertID == certID
		if ui.PendingCadesConfirm && !confirmingCades {
			ui.PendingCadesConfirm = false
			ui.PendingCadesFile = ""
			ui.PendingCadesCertID = ""
		}
		if confirmingCades {
			format = "cades"
			ui.PendingCadesConfirm = false
			ui.PendingCadesFile = ""
			ui.PendingCadesCertID = ""
		}

		ui.StatusMsg = fmt.Sprintf("Firmando (%s)...", format)
		ui.Window.Invalidate()

		var stopWait chan struct{}
		defer func() {
			if stopWait != nil {
				close(stopWait)
			}
		}()

		// Java-compatible active waiting while user signs and result is uploaded.
		if ui.Protocol != nil && ui.Protocol.ActiveWaiting && ui.Protocol.STServlet != "" && ui.Protocol.RequestID != "" {
			log.Printf("[UI] Starting active WAIT loop for sign (id=%s)", ui.Protocol.RequestID)
			stopWait = make(chan struct{})
			ui.PendingWork.Add(1)
			go func() {
				defer ui.PendingWork.Done()

				if err := ui.Protocol.SendWaitSignal(); err != nil {
					log.Printf("[UI] WAIT initial send failed: %v", err)
				}

				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-stopWait:
						return
					case <-ticker.C:
						if err := ui.Protocol.SendWaitSignal(); err != nil {
							log.Printf("[UI] WAIT periodic send failed: %v", err)
						}
					}
				}
			}()
		}

		// PIN is not needed for system store usually, or handled by OS prompt
		effectiveFormat := format
		var signOptions map[string]interface{}
		if ui.Protocol != nil {
			signOptions = buildProtocolSignOptions(ui.Protocol, effectiveFormat)
		}
		if ui.ChkStrictCompat.Value {
			signOptions = applyStrictCompatDefaults(signOptions, effectiveFormat)
		}
		if strings.EqualFold(effectiveFormat, "pades") && ui.Protocol == nil {
			signOptions = mergeSignOptions(signOptions, ui.buildPadesSignatureOptions())
		}
		signatureB64, err := protocolSignOperation(opAction, dataB64, certID, "", effectiveFormat, signOptions)
		if err != nil {
			ui.updateSessionDiagnostics("ui-local", opAction, getProtocolSessionID(ui.Protocol), effectiveFormat, "error_firma")
			// Desktop prompt for Windows with non-exportable key:
			// PAdES requires P12 in current implementation.
			if runtime.GOOS == "windows" && ui.Protocol == nil && strings.EqualFold(effectiveFormat, "pades") && isNonExportablePrivateKeyMsg(err) {
				ui.PendingCadesConfirm = true
				ui.PendingCadesFile = filePath
				ui.PendingCadesCertID = certID
				ui.StatusMsg = "Este certificado no permite PAdES (clave no exportable). Pulse 'Firmar PDF' de nuevo para firmar en CAdES."
				ui.Window.Invalidate()
				return
			}
			if err != nil {
				ui.StatusMsg = buildUserSignErrorMessage(err, effectiveFormat)
				ui.Window.Invalidate()
				return
			}
		}
		ui.updateSessionDiagnostics("ui-local", opAction, getProtocolSessionID(ui.Protocol), effectiveFormat, "firma_ok")

		// Save to file
		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			ui.StatusMsg = "Error decodificando la firma: " + err.Error()
			ui.Window.Invalidate()
			return
		}

		// Append _firmado, adapting extension to actual signature format
		ext = filepath.Ext(filePath)
		base := strings.TrimSuffix(filePath, ext)
		outPath := base + "_firmado" + ext
		switch strings.ToLower(effectiveFormat) {
		case "cades":
			outPath = base + "_firmado.csig"
		case "xades":
			outPath = base + "_firmado.xsig"
		}

		// Only save to disk if NOT in Server/Protocol mode (unless it's a temp file, but here we mean user output)
		// Actually, standard Autofirma MIGHT save it to a temp path, but users complain about "Saved in..." message.
		// If we are in Protocol mode, we usually don't want to persist the file in the input directory OR we want to suppress the message.
		// BUT: The original logic replaced extension.

		saveToDisk := true
		if ui.IsServerMode || (ui.Protocol != nil) {
			saveToDisk = false
		}

		if saveToDisk {
			if err := os.WriteFile(outPath, signature, 0644); err != nil {
				ui.StatusMsg = "Error guardando el archivo firmado: " + err.Error()
				ui.Window.Invalidate()
				return
			}
		}

		// Handle Web Protocol Upload
		if ui.Protocol != nil {
			// Signal window to close immediately for "instant" feel if it was a one-shot launch
			// BUT if we are in WebSocket mode (server running), we don't want to close the whole app.
			// However, for now, afirma://sign? one-shot is the primary use of ShouldClose.

			log.Println("[UI] Attempting to upload signature to server...")

			// Get certificate DER content
			certDER := ui.Certs[ui.SelectedCert].Content
			certB64 := base64.StdEncoding.EncodeToString(certDER)

			// 1. Send to external callers (like WebSocket server)
			res := SignatureResult{
				SignatureB64: signatureB64,
				CertDER:      ui.Certs[ui.SelectedCert].Content,
			}

			// Non-blocking send if possible, but for WebSocket flow we rely on this.
			// The WebSocket server loop waits on this channel.
			select {
			case ui.SignatureDone <- res:
				log.Println("[UI] Signature sent to internal channel (WebSocket listener).")
			default:
				log.Println("[UI] Warning: No listener on SignatureDone channel (not in WS mode or blocked?).")
				// If we are strictly in server mode, we really should have a listener.
				if ui.IsServerMode {
					// Force send? Or just log warning.
					// If we block here, we might freeze UI if server logic died.
				}
			}

			// 2. Perform server upload only if legacy protocol parameters are present
			// AND we are NOT prioritizing the WebSocket return channel logic above.
			// Actually, legacy protocols (afirma://sign?...) might use HTTP upload via RTServlet/STServlet.
			// WebSocket flows usually get the result back via the socket, NOT via upload.
			// We check if we have Servlets defined.
			isLegacyUpload := ui.Protocol.STServlet != "" || ui.Protocol.RTServlet != ""

			if isLegacyUpload {
				log.Println("[UI] Iniciando subida HTTP legacy...")
				if err := ui.Protocol.UploadSignature(signatureB64, certB64); err != nil {
					log.Printf("[UI] Fallo en subida legacy: %v", err)
					ui.updateSessionDiagnostics("subida-legacy", opAction, getProtocolSessionID(ui.Protocol), effectiveFormat, "error_subida_afirma")
					ui.StatusMsg = buildAfirmaUploadErrorMessage(err, ui.Protocol.STServlet, ui.Protocol.RTServlet)
					ui.Window.Invalidate()
					return
				} else {
					ui.updateSessionDiagnostics("subida-legacy", opAction, getProtocolSessionID(ui.Protocol), effectiveFormat, "subida_ok")
					log.Println("[UI] Subida legacy completada.")
				}
			} else {
				log.Println("[UI] Sin STServlet/RTServlet, se omite subida legacy (retorno por WebSocket).")
			}

			// 3. Manage Window State
			// If ServerMode (WebSocket), we DO NOT close. We reset state.
			// If One-Shot Protocol (afirma://sign...), we close.
			if ui.IsServerMode || (serverModeFlag != nil && *serverModeFlag) {
				// Reset for next WS request
				ui.Protocol = nil
				ui.InputFile.SetText("")
				ui.StatusMsg = "¡Firma completada! Esperando nueva solicitud..."
				ui.IsSigning = false // IMPORTANT: Release lock
				ui.Window.Invalidate()
			} else {
				// One-shot mode
				ui.ShouldClose = true
				ui.Window.Invalidate()
			}

			return
		}

		ui.StatusMsg = fmt.Sprintf("¡Firmado con éxito! Formato: %s. Guardado en: %s", strings.ToUpper(effectiveFormat), outPath)
		ui.SignedFile = outPath
		ui.PendingCadesConfirm = false
		ui.PendingCadesFile = ""
		ui.PendingCadesCertID = ""
		ui.Window.Invalidate()
	}()
}

func (ui *UI) layoutSessionDiagnostics(gtx layout.Context) layout.Dimensions {
	lines := []string{
		"Diagnóstico de sesión activa",
		"Transporte: " + safeDiagValue(ui.DiagTransport),
		"Acción: " + safeDiagValue(ui.DiagAction),
		"Sesión: " + safeDiagValue(ui.DiagSessionID),
		"Formato: " + safeDiagValue(ui.DiagFormat),
		"Resultado: " + safeDiagValue(ui.DiagLastResult),
		"Actualizado: " + safeDiagValue(ui.DiagLastUpdateTime),
	}
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body1(ui.Theme, lines[0])
				lbl.Color = color.NRGBA{R: 40, G: 40, B: 40, A: 255}
				return lbl.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(4)}.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(ui.Theme, strings.Join(lines[1:], " | "))
				lbl.Color = color.NRGBA{R: 80, G: 80, B: 80, A: 255}
				return lbl.Layout(gtx)
			}),
		)
	})
}

func safeDiagValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	return v
}

func getProtocolSessionID(p *ProtocolState) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(getQueryParam(p.Params, "idsession", "idSession"))
}

func (ui *UI) updateSessionDiagnostics(transport, action, sessionID, format, result string) {
	ui.DiagTransport = strings.TrimSpace(transport)
	ui.DiagAction = strings.TrimSpace(action)
	ui.DiagSessionID = applog.MaskID(strings.TrimSpace(sessionID))
	ui.DiagFormat = strings.TrimSpace(format)
	ui.DiagLastResult = strings.TrimSpace(result)
	ui.DiagLastUpdateTime = time.Now().Format("2006-01-02 15:04:05")
	log.Printf(
		"[UI-DIAG] transport=%s action=%s session=%s format=%s result=%s",
		safeDiagValue(ui.DiagTransport),
		safeDiagValue(ui.DiagAction),
		safeDiagValue(ui.DiagSessionID),
		safeDiagValue(ui.DiagFormat),
		safeDiagValue(ui.DiagLastResult),
	)
	if ui.Window != nil {
		ui.Window.Invalidate()
	}
}

func (ui *UI) validateSignPreconditions(filePath string, format string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("no se puede leer el fichero")
	}
	if info.IsDir() {
		return fmt.Errorf("la ruta seleccionada es una carpeta, no un fichero")
	}
	if info.Size() == 0 {
		return fmt.Errorf("el fichero está vacío")
	}
	if ui.ChkStrictCompat.Value && ui.Protocol != nil {
		hasIDSession := strings.TrimSpace(getProtocolSessionID(ui.Protocol)) != ""
		hasServlet := strings.TrimSpace(ui.Protocol.STServlet) != "" || strings.TrimSpace(ui.Protocol.RTServlet) != ""
		if !hasIDSession && !hasServlet {
			return fmt.Errorf("modo estricto: falta idsession o servlet para el flujo protocolario")
		}
	}
	return nil
}

func (ui *UI) runLocalHealthCheck() {
	ui.HealthCheckRunning = true
	ui.HealthStatus = "Ejecutando chequeo local..."
	ui.Window.Invalidate()
	defer func() {
		ui.HealthCheckRunning = false
		ui.Window.Invalidate()
	}()

	lines := []string{}
	if trustLines, err := localTLSTrustStatus(); err == nil {
		lines = append(lines, trustLines...)
	} else {
		lines = append(lines, "[Health] trust-status error: "+err.Error())
	}
	certs, err := certstore.GetSystemCertificates()
	if err != nil {
		lines = append(lines, "[Health] certstore error: "+err.Error())
	} else {
		signable := 0
		for _, c := range certs {
			if c.CanSign {
				signable++
			}
		}
		lines = append(lines, fmt.Sprintf("[Health] certificates=%d signable=%d", len(certs), signable))
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:63117", 800*time.Millisecond)
	if err != nil {
		lines = append(lines, "[Health] websocket port 63117: no listener")
	} else {
		_ = conn.Close()
		lines = append(lines, "[Health] websocket port 63117: listener detected")
	}

	ui.HealthStatus = strings.Join(lines, " | ")
}

func (ui *UI) runProblemFinder() {
	ui.ProblemScanRunning = true
	ui.HealthStatus = "Analizando causa probable del problema..."
	ui.Window.Invalidate()
	defer func() {
		ui.ProblemScanRunning = false
		ui.Window.Invalidate()
	}()

	var lines []string
	if _, err := exec.LookPath("openssl"); err != nil {
		lines = append(lines, "Causa probable: falta OpenSSL en el sistema.")
		lines = append(lines, "Acción: instala openssl y reintenta.")
	}
	if _, err := exec.LookPath("pk12util"); err != nil {
		lines = append(lines, "Causa probable: falta pk12util (NSS tools).")
		lines = append(lines, "Acción: instala libnss3-tools y reintenta.")
	}

	certs, err := certstore.GetSystemCertificates()
	if err != nil {
		lines = append(lines, "Causa probable: no se pudo leer el almacén de certificados.")
		lines = append(lines, "Detalle: "+summarizeServerBody(err.Error()))
	} else {
		signable := 0
		for _, c := range certs {
			if c.CanSign {
				signable++
			}
		}
		if len(certs) == 0 {
			lines = append(lines, "Causa probable: no hay certificados instalados.")
		} else if signable == 0 {
			lines = append(lines, "Causa probable: hay certificados, pero ninguno apto para firma (caducado/no válido/uso no permitido).")
		}
	}

	if ui.Protocol != nil {
		if host := describeAfirmaEndpoint(ui.Protocol.STServlet, ui.Protocol.RTServlet); host != "" {
			if err := checkEndpointReachability(ui.Protocol.STServlet, ui.Protocol.RTServlet); err != nil {
				lines = append(lines, "Causa probable externa: no se alcanza el servidor @firma ("+host+").")
				lines = append(lines, "Detalle: "+summarizeServerBody(err.Error()))
			}
		}
	}

	errHints := collectRecentErrorHints(resolveCurrentLogFile())
	lines = append(lines, errHints...)

	if ui.IsSigning {
		lines = append(lines, "Prueba activa de firma omitida: hay una operación de firma/verificación en curso.")
	} else {
		lines = append(lines, ui.runSelectedCertProbe()...)
	}

	if len(lines) == 0 {
		lines = append(lines, "No se detectó un fallo local claro.")
		lines = append(lines, "Si el error persiste, puede ser incidencia temporal del servidor @firma o de la sede.")
	}
	ui.HealthStatus = strings.Join(lines, " | ")
}

func (ui *UI) runSelectedCertProbe() []string {
	if ui.SelectedCert < 0 || ui.SelectedCert >= len(ui.Certs) {
		return []string{"Prueba de firma local: no ejecutada (selecciona un certificado)."}
	}
	cert := ui.Certs[ui.SelectedCert]
	probeB64 := base64.StdEncoding.EncodeToString([]byte("autofirma-problem-finder-probe"))
	_, err := signer.SignData(probeB64, cert.ID, "", "cades", nil)
	if err != nil {
		ui.updateSessionDiagnostics("diagnostico-local", "firma", "", "cades", "prueba_error")
		return []string{
			"Prueba de firma local: error con certificado seleccionado.",
			buildUserSignErrorMessage(err, "cades"),
		}
	}
	ui.updateSessionDiagnostics("diagnostico-local", "firma", "", "cades", "prueba_ok")
	return []string{"Prueba de firma local: OK (el certificado y el entorno local responden)."}
}

func checkEndpointReachability(stServlet string, rtServlet string) error {
	raw := strings.TrimSpace(stServlet)
	if raw == "" {
		raw = strings.TrimSpace(rtServlet)
	}
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := strings.TrimSpace(u.Host)
	if host == "" {
		return fmt.Errorf("host vacío en servlet")
	}
	if !strings.Contains(host, ":") {
		if strings.EqualFold(u.Scheme, "https") {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func collectRecentErrorHints(logFile string) []string {
	lines := readRecentSanitizedLogLines(logFile, 80)
	var hints []string
	joined := strings.ToLower(strings.Join(lines, " | "))
	switch {
	case strings.Contains(joined, "upload failed"), strings.Contains(joined, "fallo en subida"):
		hints = append(hints, "Se detectó fallo reciente al subir resultado a @firma (legacy upload).")
	case strings.Contains(joined, "upload http error"):
		hints = append(hints, "Se detectó rechazo HTTP reciente del servidor @firma.")
	case strings.Contains(joined, "no such host"), strings.Contains(joined, "name or service not known"):
		hints = append(hints, "Se detectó fallo DNS reciente hacia servidor de firma.")
	case strings.Contains(joined, "connection refused"), strings.Contains(joined, "no route to host"):
		hints = append(hints, "Se detectó fallo de conectividad de red reciente hacia servidor externo.")
	case strings.Contains(joined, "pk12util"), strings.Contains(joined, "openssl"):
		hints = append(hints, "Se detectó fallo criptográfico local reciente (openssl/pk12util).")
	case strings.Contains(joined, "certificado no encontrado"):
		hints = append(hints, "Se detectó selección de certificado no disponible.")
	case strings.Contains(joined, "no permite exportar su clave privada"), strings.Contains(joined, "clave no exportable"):
		hints = append(hints, "Se detectó uso de clave no exportable para el formato elegido.")
	}
	return hints
}

func (ui *UI) copyTechnicalReport() {
	report := ui.buildTechnicalReport()
	if err := copyToClipboard(report); err != nil {
		reportPath, saveErr := writeTechnicalReportFile(report)
		if saveErr != nil {
			ui.HealthStatus = "No se pudo copiar ni guardar el reporte: " + err.Error()
			log.Printf("[Reporte] Error al copiar: %v", err)
			log.Printf("[Reporte] Error al guardar respaldo: %v", saveErr)
			ui.Window.Invalidate()
			return
		}
		ui.HealthStatus = "No se pudo copiar al portapapeles. Reporte guardado en: " + reportPath
		log.Printf("[Reporte] Error al copiar: %v", err)
		log.Printf("[Reporte] Reporte guardado en: %s", reportPath)
		ui.Window.Invalidate()
		return
	}
	ui.HealthStatus = "Reporte técnico copiado al portapapeles."
	ui.Window.Invalidate()
}

func (ui *UI) buildTechnicalReport() string {
	logFile := resolveCurrentLogFile()
	lines := []string{
		"Autofirma Dipgra - Reporte técnico",
		"timestamp=" + time.Now().Format(time.RFC3339),
		"version=" + version.CurrentVersion,
		"server_mode=" + fmt.Sprintf("%t", ui.IsServerMode),
		"strict_compat=" + fmt.Sprintf("%t", ui.ChkStrictCompat.Value),
		"diag_transport=" + safeDiagValue(ui.DiagTransport),
		"diag_action=" + safeDiagValue(ui.DiagAction),
		"diag_session=" + safeDiagValue(ui.DiagSessionID),
		"diag_format=" + safeDiagValue(ui.DiagFormat),
		"diag_result=" + safeDiagValue(ui.DiagLastResult),
		"status=" + strings.TrimSpace(ui.StatusMsg),
		"update_status=" + strings.TrimSpace(ui.UpdateStatus),
		"health_status=" + strings.TrimSpace(ui.HealthStatus),
		"log_dir=" + resolveLogDirectory(),
		"log_file=" + strings.TrimSpace(logFile),
	}
	if trustLines, err := localTLSTrustStatus(); err == nil {
		for _, l := range trustLines {
			lines = append(lines, "trust="+l)
		}
	}
	for _, l := range readRecentSanitizedLogLines(logFile, 40) {
		lines = append(lines, "log="+l)
	}
	return strings.Join(lines, "\n")
}

func writeTechnicalReportFile(report string) (string, error) {
	reportDir := filepath.Join(os.TempDir(), "AutofirmaDipgra", "reports")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(reportDir, "technical-report-"+time.Now().Format("20060102-150405")+".txt")
	if err := os.WriteFile(path, []byte(report), 0644); err != nil {
		return "", err
	}
	return path, nil
}

func resolveCurrentLogFile() string {
	if p := strings.TrimSpace(applog.Path()); p != "" {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	logDir := resolveLogDirectory()
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return ""
	}
	var newestPath string
	var newestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if newestPath == "" || info.ModTime().After(newestTime) {
			newestPath = filepath.Join(logDir, entry.Name())
			newestTime = info.ModTime()
		}
	}
	return newestPath
}

func readRecentSanitizedLogLines(path string, maxLines int) []string {
	if maxLines < 1 {
		maxLines = 1
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return []string{"log_unavailable"}
	}
	f, err := os.Open(path)
	if err != nil {
		return []string{"log_open_error=" + err.Error()}
	}
	defer f.Close()

	const bufferSize = 300
	scanner := bufio.NewScanner(f)
	rawTail := make([]string, 0, bufferSize)
	for scanner.Scan() {
		rawTail = append(rawTail, scanner.Text())
		if len(rawTail) > bufferSize {
			rawTail = rawTail[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return []string{"log_scan_error=" + err.Error()}
	}
	if len(rawTail) == 0 {
		return []string{"log_empty"}
	}

	relevant := make([]string, 0, len(rawTail))
	for _, line := range rawTail {
		if isDiagnosticLogLine(line) {
			relevant = append(relevant, line)
		}
	}
	source := rawTail
	if len(relevant) > 0 {
		source = relevant
	}
	if len(source) > maxLines {
		source = source[len(source)-maxLines:]
	}

	out := make([]string, 0, len(source))
	for _, line := range source {
		out = append(out, sanitizeReportLogLine(line))
	}
	return out
}

func isDiagnosticLogLine(line string) bool {
	l := strings.ToLower(line)
	return strings.Contains(l, "[ui-diag]") ||
		strings.Contains(l, "[websocket]") ||
		strings.Contains(l, "[protocol]") ||
		strings.Contains(l, "[signer]") ||
		strings.Contains(l, "[trust]")
}

var afirmaURIRegex = regexp.MustCompile(`afirma://\S+`)
var uploadHTTPStatusRegex = regexp.MustCompile(`upload http error:\s*(\d+)`)

func sanitizeReportLogLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "-"
	}
	trimmed = afirmaURIRegex.ReplaceAllStringFunc(trimmed, applog.SanitizeURI)
	if len(trimmed) > 260 {
		return trimmed[:260] + "...(trunc)"
	}
	return trimmed
}

func buildAfirmaUploadErrorMessage(err error, stServlet string, rtServlet string) string {
	if err == nil {
		return "Error enviando la firma a @firma."
	}
	raw := strings.TrimSpace(err.Error())
	if raw == "" {
		return "Error enviando la firma a @firma."
	}
	lower := strings.ToLower(raw)
	endpoint := describeAfirmaEndpoint(stServlet, rtServlet)
	if endpoint == "" {
		endpoint = "servidor de @firma"
	}

	if strings.Contains(lower, "no such host") || strings.Contains(lower, "name or service not known") {
		return fmt.Sprintf("No se pudo resolver el DNS de %s. Revise red/VPN y la URL de @firma.", endpoint)
	}
	if strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded") {
		return fmt.Sprintf("El %s no respondió a tiempo. Puede ser una caída temporal del servicio @firma.", endpoint)
	}
	if strings.Contains(lower, "connection refused") || strings.Contains(lower, "no route to host") {
		return fmt.Sprintf("No se pudo conectar con %s (conexión rechazada o sin ruta).", endpoint)
	}
	if strings.Contains(lower, "tls:") || strings.Contains(lower, "x509:") || strings.Contains(lower, "certificate") {
		return fmt.Sprintf("Falló la conexión TLS con %s. Revise certificados de confianza/proxy.", endpoint)
	}
	if m := uploadHTTPStatusRegex.FindStringSubmatch(lower); len(m) == 2 {
		switch m[1] {
		case "400":
			return fmt.Sprintf("%s devolvió HTTP 400 (petición inválida). Parámetros incompatibles o sesión expirada.", endpoint)
		case "401", "403":
			return fmt.Sprintf("%s rechazó la petición (HTTP %s). Falta autenticación o permisos en @firma.", endpoint, m[1])
		case "404":
			return fmt.Sprintf("El endpoint de %s no existe (HTTP 404). Revise STServlet/RTServlet.", endpoint)
		case "409":
			return fmt.Sprintf("%s devolvió conflicto de sesión (HTTP 409). Reintente la operación.", endpoint)
		case "413":
			return fmt.Sprintf("%s rechazó el tamaño de la firma (HTTP 413).", endpoint)
		case "429":
			return fmt.Sprintf("%s está limitando peticiones (HTTP 429). Espere y reintente.", endpoint)
		}
		if strings.HasPrefix(m[1], "5") {
			return fmt.Sprintf("%s devolvió HTTP %s. Incidencia temporal en @firma.", endpoint, m[1])
		}
		return fmt.Sprintf("Error HTTP %s al enviar la firma a %s.", m[1], endpoint)
	}
	if strings.Contains(lower, "server upload returned non-ok body") {
		return fmt.Sprintf("%s devolvió respuesta no válida al guardar la firma. Detalle: %s", endpoint, summarizeServerBody(raw))
	}
	return fmt.Sprintf("Error enviando la firma a %s. Detalle técnico: %s", endpoint, summarizeServerBody(raw))
}

func describeAfirmaEndpoint(stServlet string, rtServlet string) string {
	raw := strings.TrimSpace(stServlet)
	if raw == "" {
		raw = strings.TrimSpace(rtServlet)
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return "endpoint de @firma"
	}
	return u.Host
}

func summarizeServerBody(raw string) string {
	if idx := strings.LastIndex(raw, ":"); idx >= 0 && idx < len(raw)-1 {
		raw = raw[idx+1:]
	}
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\n", " "))
	if len(raw) > 140 {
		return raw[:140] + "...(trunc)"
	}
	if raw == "" {
		return "sin detalle"
	}
	return raw
}

func copyToClipboard(text string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Set-Clipboard -Value @'\n"+text+"\n'@")
		configureGUICommand(cmd)
		return cmd.Run()
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		configureGUICommand(cmd)
		return cmd.Run()
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd := exec.Command("wl-copy")
			cmd.Stdin = strings.NewReader(text)
			configureGUICommand(cmd)
			return cmd.Run()
		}
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(text)
		configureGUICommand(cmd)
		return cmd.Run()
	}
}

func (ui *UI) buildPadesSignatureOptions() map[string]interface{} {
	if !ui.ChkVisibleSeal.Value {
		return nil
	}

	pageW := ui.PDFPageWidthPt
	pageH := ui.PDFPageHeightPt
	if pageW <= 0 || pageH <= 0 {
		pageW, pageH = 595.28, 841.89
	}

	x := clamp01(ui.PadesSealX) * pageW
	y := clamp01(ui.PadesSealY) * pageH
	w := clamp01(ui.PadesSealW) * pageW
	h := clamp01(ui.PadesSealH) * pageH
	if w < 20 {
		w = 20
	}
	if h < 14 {
		h = 14
	}

	return map[string]interface{}{
		"visibleSignature": true,
		"page":             ui.PadesSealPage,
		"x":                x,
		"y":                y,
		"width":            w,
		"height":           h,
	}
}

func normalizeCheckIssue(err error) string {
	if err == nil {
		return "error de firma de prueba"
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "error de firma de prueba"
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "no permite exportar su clave privada"):
		return "clave privada no exportable y firma en almacen no disponible"
	case strings.Contains(lower, "fallo al firmar en el almacen de windows"):
		return "clave privada presente pero no usable por el proveedor criptografico"
	case strings.Contains(lower, "certificado no encontrado"):
		return "certificado no disponible en el almacen"
	default:
		return msg
	}
}

func buildUserSignErrorMessage(err error, format string) string {
	if err == nil {
		return "Error al firmar."
	}
	raw := strings.TrimSpace(err.Error())
	if raw == "" {
		return "Error al firmar."
	}
	lower := strings.ToLower(raw)
	fmtLabel := strings.ToUpper(strings.TrimSpace(format))
	if fmtLabel == "" {
		fmtLabel = "AUTO"
	}

	if strings.Contains(lower, "certificado no encontrado") {
		return "No se pudo usar el certificado seleccionado. Puede haberse retirado del almacén o token."
	}
	if strings.Contains(lower, "certificado caducado") {
		return "El certificado está caducado y no puede usarse para firmar."
	}
	if strings.Contains(lower, "aun no valido") || strings.Contains(lower, "aún no válido") {
		return "El certificado todavía no es válido (fecha/hora del sistema o vigencia del certificado)."
	}
	if strings.Contains(lower, "no permite exportar su clave privada") || strings.Contains(lower, "clave no exportable") {
		if strings.EqualFold(format, "pades") {
			return "El certificado no permite PAdES con este método (clave no exportable). Pruebe CAdES o certificado software."
		}
		return "El certificado no permite usar su clave privada para esta operación."
	}
	if strings.Contains(lower, "pin") || strings.Contains(lower, "pkcs11") || strings.Contains(lower, "smartcard") || strings.Contains(lower, "token") {
		return "No se pudo autenticar el certificado en el dispositivo criptográfico (PIN/token/tarjeta)."
	}
	if strings.Contains(lower, "acceso denegado") || strings.Contains(lower, "permission denied") {
		return "El sistema denegó el acceso a la clave privada o al almacén de certificados."
	}
	if strings.Contains(lower, "fallo al firmar en el almacen de windows") || strings.Contains(lower, "almacen de windows") {
		return "Falló la firma en el almacén de Windows. Puede ser una restricción del proveedor criptográfico."
	}
	if strings.Contains(lower, "datos base64 inválidos") || strings.Contains(lower, "xml invalido") {
		return "Los datos de entrada para firmar son inválidos o están corruptos."
	}
	if strings.Contains(lower, "openssl") || strings.Contains(lower, "pk12util") {
		return "Falló una dependencia criptográfica local (OpenSSL/pk12util). Revise la instalación del entorno."
	}
	if strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded") {
		return "La operación de firma agotó el tiempo de espera."
	}
	return fmt.Sprintf("Error al firmar en formato %s. Detalle técnico: %s", fmtLabel, summarizeServerBody(raw))
}

func (ui *UI) checkUpdates(silent bool) {
	if ui.UpdateCheckRunning {
		return
	}
	ui.UpdateCheckRunning = true
	if !silent {
		ui.UpdateStatus = "Comprobando actualizaciones..."
		ui.Window.Invalidate()
	}
	defer func() {
		ui.UpdateCheckRunning = false
		ui.Window.Invalidate()
	}()

	updateURL := getConfiguredUpdateURL()

	result, err := updater.CheckForUpdates(version.CurrentVersion, updateURL)
	if err != nil {
		log.Printf("[Update] Error comprobando actualizaciones: %v", err)
		if !silent {
			ui.UpdateStatus = "No se pudo comprobar actualizaciones: " + err.Error()
		}
		return
	}

	ui.UpdateLatestVersion = result.LatestVersion
	ui.UpdateDownloadURL = result.UpdateURL
	if result.HasUpdate {
		ui.UpdateStatus = fmt.Sprintf("Hay una nueva version disponible: %s", result.LatestVersion)
		if !silent {
			ui.StatusMsg = ui.UpdateStatus
		}
		if strings.TrimSpace(result.UpdateURL) != "" {
			ui.UpdateStatus = ui.UpdateStatus + " (" + strings.TrimSpace(result.UpdateURL) + ")"
		}
		log.Printf("[Update] Nueva version disponible: actual=%s latest=%s url=%s", version.CurrentVersion, result.LatestVersion, result.UpdateURL)
		return
	}

	ui.UpdateStatus = fmt.Sprintf("Estas en la ultima version (%s)", version.CurrentVersion)
	if !silent {
		ui.StatusMsg = ui.UpdateStatus
	}
	log.Printf("[Update] Sin actualizaciones: version actual=%s", version.CurrentVersion)
}

func getConfiguredUpdateURL() string {
	if v := strings.TrimSpace(os.Getenv("AUTOFIRMA_UPDATE_JSON_URL")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if v := windowsRegistryUpdateURL(); v != "" {
			return v
		}
	}
	return version.DefaultUpdateURL
}

func windowsRegistryUpdateURL() string {
	cmd := exec.Command(
		"reg", "query", `HKLM\Software\Dipgra\Autofirma Dipgra`, "/v", "UpdateJsonUrl",
	)
	configureGUICommand(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[Update] No se pudo leer UpdateJsonUrl del registro: %v", err)
		return ""
	}
	// Expected line includes:
	// UpdateJsonUrl    REG_SZ    https://...
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), "updatejsonurl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		return strings.TrimSpace(strings.Join(fields[2:], " "))
	}
	return ""
}

func resolveLogDirectory() string {
	if p := strings.TrimSpace(applog.Path()); p != "" {
		return filepath.Dir(p)
	}
	if runtime.GOOS == "windows" {
		if base := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); base != "" {
			return filepath.Join(base, "AutofirmaDipgra", "logs")
		}
		if profile := strings.TrimSpace(os.Getenv("USERPROFILE")); profile != "" {
			return filepath.Join(profile, "AppData", "Local", "AutofirmaDipgra", "logs")
		}
	}
	return filepath.Join(os.TempDir(), "AutofirmaDipgra", "logs")
}

func isNonExportablePrivateKeyMsg(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "no permite exportar su clave privada") ||
		strings.Contains(msg, "clave no exportable") ||
		strings.Contains(msg, "non-exportable")
}

func certificateDisplayLabel(cert protocol.Certificate) string {
	label := ""
	if cn, ok := cert.Subject["CN"]; ok && strings.TrimSpace(cn) != "" {
		label = strings.TrimSpace(cn)
	} else if strings.TrimSpace(cert.Nickname) != "" {
		label = strings.TrimSpace(cert.Nickname)
	} else {
		label = cert.ID
	}
	if issuerCN, ok := cert.Issuer["CN"]; ok && strings.TrimSpace(issuerCN) != "" {
		label = label + " - " + strings.TrimSpace(issuerCN)
	}
	if cert.CanSign {
		return label + " [apto para firma]"
	}
	issue := strings.TrimSpace(cert.SignIssue)
	if issue == "" {
		issue = "no apto para firma"
	}
	return label + " [no apto: " + issue + "]"
}

func pickPDFPath(title string) (string, error) {
	if runtime.GOOS == "windows" {
		ps := "$ErrorActionPreference='Stop'; " +
			"Add-Type -AssemblyName System.Windows.Forms; " +
			"$dlg = New-Object System.Windows.Forms.OpenFileDialog; " +
			"$dlg.Title = '" + psQuote(title) + "'; " +
			"$dlg.Filter = 'PDF files (*.pdf)|*.pdf|All files (*.*)|*.*'; " +
			"$dlg.Multiselect = $false; " +
			"if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $dlg.FileName }"
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", ps)
		configureGUICommand(cmd)
		out, err := cmd.Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}

	// Linux/Unix path pickers.
	cmd := exec.Command("zenity", "--file-selection", "--file-filter=*.pdf", "--title="+title)
	configureGUICommand(cmd)
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	cmd = exec.Command("kdialog", "--getopenfilename", ".", "*.pdf")
	configureGUICommand(cmd)
	out, err = cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	return "", err
}

func openExternal(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("ruta o URL vacía")
	}
	switch runtime.GOOS {
	case "windows":
		lower := strings.ToLower(target)
		isURL := strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "afirma://")
		if isURL {
			// Primary strategy: Start-Process (hidden), fallback to rundll32.
			ps := "$ErrorActionPreference='Stop'; Start-Process -FilePath '" + psQuote(target) + "'"
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
			configureGUICommand(cmd)
			if err := cmd.Run(); err == nil {
				return nil
			}
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
			configureGUICommand(cmd)
			return cmd.Run()
		} else {
			clean := filepath.Clean(target)
			if abs, err := filepath.Abs(clean); err == nil {
				clean = abs
			}
			ps := "$ErrorActionPreference='Stop'; Start-Process -FilePath '" + psQuote(clean) + "'"
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
			configureGUICommand(cmd)
			if err := cmd.Run(); err == nil {
				return nil
			}
			cmd = exec.Command("explorer.exe", clean)
			configureGUICommand(cmd)
			return cmd.Run()
		}
	case "darwin":
		cmd := exec.Command("open", target)
		configureGUICommand(cmd)
		return cmd.Run()
	default:
		cmd := exec.Command("xdg-open", target)
		configureGUICommand(cmd)
		return cmd.Run()
	}
}

func openContainingFolder(filePath string) error {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return fmt.Errorf("ruta vacía")
	}
	abs := filepath.Clean(filePath)
	if p, err := filepath.Abs(abs); err == nil {
		abs = p
	}
	switch runtime.GOOS {
	case "windows":
		ps := "$ErrorActionPreference='Stop'; Start-Process -FilePath 'explorer.exe' -ArgumentList @('/select,','" + psQuote(abs) + "')"
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
		configureGUICommand(cmd)
		if err := cmd.Run(); err == nil {
			return nil
		}
		cmd = exec.Command("explorer.exe", "/select,", abs)
		configureGUICommand(cmd)
		return cmd.Run()
	case "darwin":
		cmd := exec.Command("open", "-R", abs)
		configureGUICommand(cmd)
		return cmd.Run()
	default:
		dir := filepath.Dir(abs)
		cmd := exec.Command("xdg-open", dir)
		configureGUICommand(cmd)
		return cmd.Run()
	}
}

func psQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func toWatermark(src image.Image, alpha uint8) image.Image {
	if src == nil {
		return nil
	}
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	draw.Draw(dst, b, src, b.Min, draw.Src)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			i := dst.PixOffset(x, y)
			a := dst.Pix[i+3]
			dst.Pix[i+3] = uint8((uint16(a) * uint16(alpha)) / 255)
		}
	}
	return dst
}

// Color helpers
var (
	Black = color.NRGBA{A: 255}
	White = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
)

func fill(gtx layout.Context, col color.NRGBA) layout.Dimensions {
	d := image.Point{X: gtx.Constraints.Min.X, Y: gtx.Constraints.Min.Y}
	return layout.Dimensions{Size: d}
}
