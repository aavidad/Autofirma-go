package main

import (
	"autofirma-host/pkg/certstore"
	"autofirma-host/pkg/protocol"
	"autofirma-host/pkg/signer"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

type UI struct {
	Theme  *material.Theme
	Window *app.Window

	// State for widgets
	BtnSign       widget.Clickable
	BtnVerify     widget.Clickable
	BtnBrowse     widget.Clickable
	BtnView       widget.Clickable // View current file
	BtnOpen       widget.Clickable // Open Signed PDF
	BtnOpenFolder widget.Clickable // Open Containing Folder
	BtnValide     widget.Clickable // Open Valide URL

	BtnModeSign   widget.Clickable
	BtnModeVerify widget.Clickable

	BtnAbout  widget.Clickable
	ShowAbout bool

	ListCerts    widget.List
	Certs        []protocol.Certificate
	SelectedCert int                // Index of selected cert, -1 if none
	CertClicks   []widget.Clickable // Clickable for each list item

	InputFile widget.Editor

	StatusMsg  string
	SignedFile string // Path to the last signed file

	IsSigning bool
	Mode      int // 0: Sign, 1: Verify

	Protocol *ProtocolState // Web protocol state
}

func NewUI(w *app.Window) *UI {
	ui := &UI{
		Theme:        material.NewTheme(),
		Window:       w,
		SelectedCert: -1,
		Mode:         0,
	}

	ui.ListCerts.Axis = layout.Vertical
	ui.InputFile.SingleLine = true
	ui.InputFile.Submit = true

	// Load certificates in background
	go ui.loadCertificates()

	return ui
}

func (ui *UI) browseFile() {
	title := "Seleccionar PDF para firmar"
	if ui.Mode == 1 {
		title = "Seleccionar PDF para verificar"
	}
	path, err := selectPDFWithSystemDialog(title)
	if err != nil {
		ui.StatusMsg = "Error: No se pudo abrir el dialogo de seleccion de fichero: " + err.Error()
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
	_ = openWithSystem(ui.SignedFile)
}

func (ui *UI) openFolder() {
	_ = openWithSystem(filepath.Dir(ui.SignedFile))
}

func openWithSystem(target string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	case "darwin":
		return exec.Command("open", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}

func (ui *UI) Layout(gtx layout.Context) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		// Solid White Background
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.Fill(gtx.Ops, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),

		// Content Layer
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis: layout.Vertical,
			}.Layout(gtx,
				// Header (Title Only)
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
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
												go openWithSystem(path)
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

				// Certificate List Header (Only in Sign Mode)
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if ui.Mode == 0 {
						return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return material.H6(ui.Theme, "Seleccionar Certificado:").Layout(gtx)
						})
					}
					return layout.Dimensions{}
				}),

				// Certificate List (Only in Sign Mode)
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if ui.Mode == 0 {
						return material.List(ui.Theme, &ui.ListCerts).Layout(gtx, len(ui.Certs), func(gtx layout.Context, index int) layout.Dimensions {
							// Handle Click
							if ui.CertClicks[index].Clicked(gtx) {
								ui.SelectedCert = index
								ui.Window.Invalidate()
							}

							label := ui.Certs[index].Nickname
							if label == "" {
								label = ui.Certs[index].ID
							}
							item := material.Button(ui.Theme, &ui.CertClicks[index], label)
							item.Background = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
							item.Color = color.NRGBA{A: 255} // Black text
							if index == ui.SelectedCert {
								item.Background = color.NRGBA{R: 200, G: 200, B: 255, A: 255} // Highlight
							}

							return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return item.Layout(gtx)
							})
						})
					}
					return layout.Dimensions{}
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
												_ = openWithSystem("https://valide.redsara.es/valide/validarFirma/ejecutar.html")
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
										return material.Body2(ui.Theme, "Creado por Alberto Avidad Fernandez de Atencion Informática a Municipios").Layout(gtx)
									})
								}
								return layout.Dimensions{}
							}),
						)
					})
				}),
			)
		}),
	)
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
		defer func() {
			ui.IsSigning = false
			ui.Window.Invalidate()
		}()

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

func (ui *UI) signCurrentFile() {
	if ui.SelectedCert == -1 {
		ui.StatusMsg = "Por favor, seleccione un certificado."
		ui.Window.Invalidate()
		return
	}
	certID := ui.Certs[ui.SelectedCert].ID

	filePath := ui.InputFile.Text()
	if filePath == "" {
		ui.StatusMsg = "Por favor, introduzca la ruta del PDF."
		ui.Window.Invalidate()
		return
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		ui.StatusMsg = "Error leyendo el archivo: " + err.Error()
		ui.Window.Invalidate()
		return
	}

	// Convert to Base64
	dataB64 := base64.StdEncoding.EncodeToString(data)

	// Determine format based on extension or protocol
	ext := strings.ToLower(filepath.Ext(filePath))
	format := "pades" // Default

	// If in protocol mode and format was specified, use that
	if ui.Protocol != nil && ui.Protocol.SignFormat != "" {
		format = strings.ToLower(ui.Protocol.SignFormat)
		log.Printf("[UI] Using protocol-specified format: %s", format)
	} else {
		// Auto-detect from extension
		if ext == ".xml" {
			format = "xades"
		}
	}

	// Sign
	ui.StatusMsg = fmt.Sprintf("Firmando (%s)...", format)
	ui.SignedFile = "" // Reset previous signed file
	ui.IsSigning = true
	ui.Window.Invalidate()

	// Run in background to not block UI
	go func() {
		defer func() {
			ui.IsSigning = false
			ui.Window.Invalidate()
		}()

		// PIN is not needed for system store usually, or handled by OS prompt
		signatureB64, err := signer.SignData(dataB64, certID, "", format, nil)
		if err != nil {
			ui.StatusMsg = "Error al firmar: " + err.Error()
			ui.Window.Invalidate()
			return
		}

		// Save to file
		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			ui.StatusMsg = "Error decodificando la firma: " + err.Error()
			ui.Window.Invalidate()
			return
		}

		// Append _firmado
		ext := filepath.Ext(filePath)
		base := strings.TrimSuffix(filePath, ext)
		outPath := base + "_firmado" + ext

		if err := os.WriteFile(outPath, signature, 0644); err != nil {
			ui.StatusMsg = "Error guardando el archivo firmado: " + err.Error()
			ui.Window.Invalidate()
			return
		}

		// Handle Web Protocol Upload
		if ui.Protocol != nil {
			ui.StatusMsg = "Archivo guardado. Subiendo firma al servidor..."
			ui.Window.Invalidate()

			// We might need the certificate? Passing empty for now or PEM
			// For PAdES, the signature itself usually contains the cert.
			// The retrieved 'dat' param usually expects the signature blob (PKCS#7 or PAdES equivalent).
			// For PAdES, the signature IS the PDF (or the diff).
			// Wait, SignData for PAdES returns the FULL PDF Base64 encoded?
			// Yes, typically PAdES envelopes the whole document.
			// `signer.SignData` returns `base64.StdEncoding.EncodeToString(signedData)`.
			// So `signatureB64` IS the full signed PDF.
			// So uploading it as `dat` is correct for typical `put` op.

			err := ui.Protocol.UploadSignature(signatureB64, "")
			if err != nil {
				ui.StatusMsg = "Guardado local OK. Error subida web: " + err.Error()
			} else {
				ui.StatusMsg = "¡Proceso completado! Firma subida y guardada localmente."
			}
			ui.Window.Invalidate()
			return
		}

		ui.StatusMsg = "¡Firmado con éxito! Guardado en: " + outPath
		ui.SignedFile = outPath
		ui.Window.Invalidate()
	}()
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
