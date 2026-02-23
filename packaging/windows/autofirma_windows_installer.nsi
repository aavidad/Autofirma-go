; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 Diputacion de Granada
; Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

Unicode True
!include "MUI2.nsh"

!define APPNAME "Autofirma Dipgra"
!define COMPANY "Dipgra"
!ifndef APP_VERSION
  !define APP_VERSION "0.0.23"
!endif
!ifndef UPDATE_JSON_URL
  !define UPDATE_JSON_URL "https://autofirma.dipgra.es/version.json"
!endif
!define INSTALL_DIR "$PROGRAMFILES64\AutofirmaDipgra"
!ifndef BUNDLE_DIR
  !define BUNDLE_DIR "release/windows/bundle/AutofirmaDipgra"
!endif
!ifndef OUTFILE_PATH
  !define OUTFILE_PATH "release/windows/AutofirmaDipgra-windows-installer.exe"
!endif

Name "${APPNAME}"
OutFile "${OUTFILE_PATH}"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\autofirma-desktop.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Iniciar ${APPNAME} ahora"
!define MUI_FINISHPAGE_RUN_CHECKED
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Spanish"

; --- SETTINGS ---
Section "Base de AutoFirma (Requerido)" SEC_CORE
  SectionIn RO
  SetRegView 64
  SetOutPath "$INSTDIR"
  
  ; Core binaries
  File "${BUNDLE_DIR}\autofirma-desktop.exe"
  File "${BUNDLE_DIR}\autofirma-host.exe"
  File "${BUNDLE_DIR}\autofirma.ico"
  File "${BUNDLE_DIR}\native_messaging_allowlist.json"
  
  ; Resources
  File /r "${BUNDLE_DIR}\certs"
  File /r "${BUNDLE_DIR}\config"
  File /r "${BUNDLE_DIR}\assets"
  
  ; Prepare local TLS certs
  ExecWait '"$INSTDIR\autofirma-desktop.exe" --generate-certs'
  ExecWait '"$INSTDIR\autofirma-desktop.exe" --exportar-certs-java "$INSTDIR"'
  ExecWait '"$INSTDIR\autofirma-desktop.exe" --install-trust'

  ; Browser integration registry
  WriteRegStr HKLM "Software\${COMPANY}\${APPNAME}" "Install_Dir" "$INSTDIR"
  WriteRegStr HKLM "Software\${COMPANY}\${APPNAME}" "Version" "${APP_VERSION}"
  
  ; Protocol afirma://
  WriteRegStr HKCR "afirma" "" "URL:Autofirma Protocol"
  WriteRegStr HKCR "afirma" "URL Protocol" ""
  WriteRegStr HKCR "afirma\DefaultIcon" "" "$INSTDIR\autofirma.ico,0"
  WriteRegStr HKCR "afirma\shell\open\command" "" '"$INSTDIR\autofirma-desktop.exe" "%1"'
  
  ; Uninstall info
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

SectionGroup "Interfaces de Usuario" SEC_FE
  Section "Interfaz Fyne (Go)" SEC_FYNE
    CreateShortcut "$SMPROGRAMS\Autofirma Dipgra\Autofirma Fyne.lnk" "$INSTDIR\autofirma-desktop.exe" "-frontend fyne" "$INSTDIR\autofirma.ico" 0
  SectionEnd

  Section "Interfaz Gio (Ligera)" SEC_GIO
    CreateShortcut "$SMPROGRAMS\Autofirma Dipgra\Autofirma Gio (Ligera).lnk" "$INSTDIR\autofirma-desktop.exe" "-frontend gio" "$INSTDIR\autofirma.ico" 0
  SectionEnd

  Section "Interfaz Qt 6 (Recomendada)" SEC_QT
    SetOutPath "$INSTDIR"
    File "${BUNDLE_DIR}\autofirma-desktop-qt-bin.exe"
    File "${BUNDLE_DIR}\autofirma-desktop-qt-real.exe"
    File /r "${BUNDLE_DIR}\qml"
    ; Incluir DLLs de Qt si existen
    File /nonfatal "${BUNDLE_DIR}\*.dll"
    File /nonfatal /r "${BUNDLE_DIR}\platforms"
    File /nonfatal /r "${BUNDLE_DIR}\styles"
    File /nonfatal /r "${BUNDLE_DIR}\imageformats"
    File /nonfatal /r "${BUNDLE_DIR}\tls"

    CreateShortcut "$SMPROGRAMS\Autofirma Dipgra\AutoFirma Dipgra.lnk" "$INSTDIR\autofirma-desktop-qt-bin.exe" "" "$INSTDIR\autofirma.ico" 0
    CreateShortcut "$DESKTOP\AutoFirma Dipgra.lnk" "$INSTDIR\autofirma-desktop-qt-bin.exe" "" "$INSTDIR\autofirma.ico" 0
    
    ; Update protocol to use Qt by default if installed
    WriteRegStr HKCR "afirma\shell\open\command" "" '"$INSTDIR\autofirma-desktop-qt-bin.exe" "%1"'
  SectionEnd
SectionGroupEnd

Section "Extensiones de Navegador" SEC_EXT
  SetOutPath "$INSTDIR\extensiones"
  File /r "${BUNDLE_DIR}\extensiones\*"
  
  ; Firefox deployment
  IfFileExists "$INSTDIR\extensiones\dipgra-extension-firefox.xpi" 0 +5
    CreateDirectory "$PROGRAMFILES64\Mozilla Firefox\distribution\extensions"
    CopyFiles /SILENT "$INSTDIR\extensiones\dipgra-extension-firefox.xpi" "$PROGRAMFILES64\Mozilla Firefox\distribution\extensions\extension@dipgra.es.xpi"
SectionEnd

Section "Uninstall"
  SetRegView 64
  Delete "$DESKTOP\Autofirma Dipgra.lnk"
  Delete "$SMPROGRAMS\Autofirma Dipgra\Autofirma Dipgra.lnk"
  Delete "$SMPROGRAMS\Autofirma Dipgra\Servidor AutoFirma.lnk"
  RMDir "$SMPROGRAMS\Autofirma Dipgra"

  DeleteRegKey HKCR "afirma"
  DeleteRegKey HKLM "Software\Classes\afirma"
  DeleteRegKey HKCU "Software\Classes\afirma"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
  DeleteRegKey HKLM "Software\${COMPANY}\${APPNAME}"

  RMDir /r "$INSTDIR"
SectionEnd
