//go:build windows
// +build windows

package main

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnNoChangeDir   = 0x00000008
)

type openFileName struct {
	lStructSize       uint32
	hwndOwner         windows.Handle
	hInstance         windows.Handle
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        unsafe.Pointer
	dwReserved        uint32
	flagsEx           uint32
}

var (
	comdlg32                  = windows.NewLazySystemDLL("comdlg32.dll")
	procGetOpenFileNameW      = comdlg32.NewProc("GetOpenFileNameW")
	procCommDlgExtendedErrorW = comdlg32.NewProc("CommDlgExtendedError")
)

func utf16WithEmbeddedNUL(s string) []uint16 {
	u := utf16.Encode([]rune(s))
	if len(u) == 0 || u[len(u)-1] != 0 {
		u = append(u, 0)
	}
	return u
}

func selectPDFWithSystemDialog(title string) (string, error) {
	filter := utf16WithEmbeddedNUL("PDF files (*.pdf)\x00*.pdf\x00All files (*.*)\x00*.*\x00\x00")
	fileBuf := make([]uint16, 32768)
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return "", err
	}

	ofn := openFileName{
		lStructSize: uint32(unsafe.Sizeof(openFileName{})),
		lpstrFilter: &filter[0],
		lpstrFile:   &fileBuf[0],
		nMaxFile:    uint32(len(fileBuf)),
		lpstrTitle:  titlePtr,
		flags:       ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir,
	}

	ret, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		extErr, _, _ := procCommDlgExtendedErrorW.Call()
		if extErr == 0 {
			return "", nil
		}
		return "", fmt.Errorf("GetOpenFileNameW fallo (codigo %d)", extErr)
	}

	return windows.UTF16ToString(fileBuf), nil
}
