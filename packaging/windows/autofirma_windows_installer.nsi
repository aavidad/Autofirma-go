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
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Spanish"

Section "Install"
  SetRegView 64
  SetOutPath "$INSTDIR"
  File /r "${BUNDLE_DIR}/*"
  ExecWait '"$INSTDIR\autofirma-desktop.exe" --generate-certs'

  ; Main executable
  WriteRegStr HKLM "Software\${COMPANY}\${APPNAME}" "Install_Dir" "$INSTDIR"
  WriteRegStr HKLM "Software\${COMPANY}\${APPNAME}" "Version" "${APP_VERSION}"
  WriteRegStr HKLM "Software\${COMPANY}\${APPNAME}" "UpdateJsonUrl" "${UPDATE_JSON_URL}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${COMPANY}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "URLUpdateInfo" "${UPDATE_JSON_URL}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1

  ; afirma:// protocol
  WriteRegStr HKCR "afirma" "" "URL:Autofirma Protocol"
  WriteRegStr HKCR "afirma" "URL Protocol" ""
  WriteRegStr HKCR "afirma\DefaultIcon" "" "$INSTDIR\autofirma.ico,0"
  WriteRegStr HKCR "afirma\shell\open\command" "" '"$INSTDIR\autofirma-desktop.exe" "%1"'
  ; Also register directly under Software\Classes for browser compatibility
  WriteRegStr HKLM "Software\Classes\afirma" "" "URL:Autofirma Protocol"
  WriteRegStr HKLM "Software\Classes\afirma" "URL Protocol" ""
  WriteRegStr HKLM "Software\Classes\afirma\DefaultIcon" "" "$INSTDIR\autofirma.ico,0"
  WriteRegStr HKLM "Software\Classes\afirma\shell\open\command" "" '"$INSTDIR\autofirma-desktop.exe" "%1"'
  WriteRegStr HKCU "Software\Classes\afirma" "" "URL:Autofirma Protocol"
  WriteRegStr HKCU "Software\Classes\afirma" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\afirma\DefaultIcon" "" "$INSTDIR\autofirma.ico,0"
  WriteRegStr HKCU "Software\Classes\afirma\shell\open\command" "" '"$INSTDIR\autofirma-desktop.exe" "%1"'

  CreateDirectory "$SMPROGRAMS\Autofirma Dipgra"
  CreateShortcut "$SMPROGRAMS\Autofirma Dipgra\Autofirma Dipgra.lnk" "$INSTDIR\autofirma-desktop.exe" "" "$INSTDIR\autofirma.ico" 0
  CreateShortcut "$DESKTOP\Autofirma Dipgra.lnk" "$INSTDIR\autofirma-desktop.exe" "" "$INSTDIR\autofirma.ico" 0

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  SetRegView 64
  Delete "$DESKTOP\Autofirma Dipgra.lnk"
  Delete "$SMPROGRAMS\Autofirma Dipgra\Autofirma Dipgra.lnk"
  RMDir "$SMPROGRAMS\Autofirma Dipgra"

  DeleteRegKey HKCR "afirma"
  DeleteRegKey HKLM "Software\Classes\afirma"
  DeleteRegKey HKCU "Software\Classes\afirma"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
  DeleteRegKey HKLM "Software\${COMPANY}\${APPNAME}"

  RMDir /r "$INSTDIR"
SectionEnd
