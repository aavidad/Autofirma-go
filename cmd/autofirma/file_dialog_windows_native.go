//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ofnExplorer         = 0x00080000
	ofnPathMustExist    = 0x00000800
	ofnFileMustExist    = 0x00001000
	ofnOverWritePrompt  = 0x00000002
	ofnAllowMultiSelect = 0x00000200
	invalidFileAttrs    = ^uint32(0)
)

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
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
	comdlg32DLL            = windows.NewLazySystemDLL("comdlg32.dll")
	procGetOpenFileNameW   = comdlg32DLL.NewProc("GetOpenFileNameW")
	procGetSaveFileNameW   = comdlg32DLL.NewProc("GetSaveFileNameW")
	procCommDlgExtendedErr = comdlg32DLL.NewProc("CommDlgExtendedError")
)

func nativeOpenFileDialogWindows(title, initialPath, exts string, multi bool) ([]string, bool, error) {
	filter, err := buildNativeWinFilter(exts, true)
	if err != nil {
		return nil, false, err
	}
	titlePtr, _ := windows.UTF16PtrFromString(strings.TrimSpace(title))
	initDirPtr := utf16PtrOrNil(resolveInitialDir(initialPath))

	fileBuf := make([]uint16, 65536)
	ofn := openFileName{
		lStructSize:     uint32(unsafe.Sizeof(openFileName{})),
		lpstrFilter:     filter,
		lpstrFile:       &fileBuf[0],
		nMaxFile:        uint32(len(fileBuf)),
		lpstrInitialDir: initDirPtr,
		lpstrTitle:      titlePtr,
		flags:           ofnExplorer | ofnPathMustExist | ofnFileMustExist,
	}
	if multi {
		ofn.flags |= ofnAllowMultiSelect
	}
	r1, _, callErr := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r1 == 0 {
		code, _, _ := procCommDlgExtendedErr.Call()
		if code == 0 {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("GetOpenFileNameW falló (code=%d): %v", code, callErr)
	}
	items := parseMultiString(fileBuf)
	if len(items) == 0 {
		return nil, true, nil
	}
	if len(items) == 1 {
		return []string{items[0]}, false, nil
	}
	base := items[0]
	out := make([]string, 0, len(items)-1)
	for _, name := range items[1:] {
		out = append(out, filepath.Join(base, name))
	}
	return out, false, nil
}

func nativeSaveFileDialogWindows(title, defaultPath, exts string) (string, bool, error) {
	filter, err := buildNativeWinFilter(exts, true)
	if err != nil {
		return "", false, err
	}
	titlePtr, _ := windows.UTF16PtrFromString(strings.TrimSpace(title))
	initDirPtr := utf16PtrOrNil(filepath.Dir(strings.TrimSpace(defaultPath)))

	fileBuf := make([]uint16, 65536)
	def := strings.TrimSpace(defaultPath)
	if def != "" {
		defU16, _ := windows.UTF16FromString(def)
		copy(fileBuf, defU16)
	}
	ofn := openFileName{
		lStructSize:     uint32(unsafe.Sizeof(openFileName{})),
		lpstrFilter:     filter,
		lpstrFile:       &fileBuf[0],
		nMaxFile:        uint32(len(fileBuf)),
		lpstrInitialDir: initDirPtr,
		lpstrTitle:      titlePtr,
		flags:           ofnExplorer | ofnPathMustExist | ofnOverWritePrompt,
	}
	r1, _, callErr := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r1 == 0 {
		code, _, _ := procCommDlgExtendedErr.Call()
		if code == 0 {
			return "", true, nil
		}
		return "", false, fmt.Errorf("GetSaveFileNameW falló (code=%d): %v", code, callErr)
	}
	path := windows.UTF16ToString(fileBuf)
	if strings.TrimSpace(path) == "" {
		return "", true, nil
	}
	return path, false, nil
}

func buildNativeWinFilter(exts string, includeAll bool) (*uint16, error) {
	extList := []string{}
	for _, raw := range strings.Split(strings.TrimSpace(exts), ",") {
		v := strings.TrimSpace(strings.TrimPrefix(raw, "."))
		if v != "" {
			extList = append(extList, v)
		}
	}
	pairs := []string{}
	if len(extList) == 0 {
		pairs = append(pairs, "Todos los ficheros", "*.*")
	} else {
		for _, e := range extList {
			up := strings.ToUpper(e)
			pairs = append(pairs, up+" (*."+e+")", "*."+e)
		}
		if includeAll {
			pairs = append(pairs, "Todos los ficheros", "*.*")
		}
	}
	filter := strings.Join(pairs, "\x00") + "\x00\x00"
	u16, err := windows.UTF16FromString(filter)
	if err != nil {
		return nil, err
	}
	return &u16[0], nil
}

func parseMultiString(buf []uint16) []string {
	parts := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] != 0 {
			continue
		}
		if i == start {
			break
		}
		parts = append(parts, windows.UTF16ToString(buf[start:i]))
		start = i + 1
	}
	return parts
}

func utf16PtrOrNil(v string) *uint16 {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	p, err := windows.UTF16PtrFromString(v)
	if err != nil {
		return nil
	}
	return p
}

func resolveInitialDir(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if st, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path)); err == nil && st != invalidFileAttrs {
		return path
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return ""
	}
	return dir
}
