//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

package main

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var (
	user32DLL            = windows.NewLazySystemDLL("user32.dll")
	kernel32DLL          = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard    = user32DLL.NewProc("OpenClipboard")
	procCloseClipboard   = user32DLL.NewProc("CloseClipboard")
	procEmptyClipboard   = user32DLL.NewProc("EmptyClipboard")
	procSetClipboardData = user32DLL.NewProc("SetClipboardData")
	procGlobalAlloc      = kernel32DLL.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32DLL.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32DLL.NewProc("GlobalUnlock")
	procGlobalFree       = kernel32DLL.NewProc("GlobalFree")
)

func nativeCopyToClipboardWindows(text string) error {
	utf16Data := utf16.Encode([]rune(text + "\x00"))
	dataLen := uintptr(len(utf16Data) * 2)
	if dataLen == 0 {
		dataLen = 2
	}

	r1, _, callErr := procOpenClipboard.Call(0)
	if r1 == 0 {
		return fmt.Errorf("OpenClipboard falló: %v", callErr)
	}
	defer procCloseClipboard.Call()

	if r1, _, callErr = procEmptyClipboard.Call(); r1 == 0 {
		return fmt.Errorf("EmptyClipboard falló: %v", callErr)
	}

	hMem, _, callErr := procGlobalAlloc.Call(gmemMoveable, dataLen)
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc falló: %v", callErr)
	}

	ptr, _, callErr := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("GlobalLock falló: %v", callErr)
	}

	copy(
		unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16Data)),
		utf16Data,
	)
	procGlobalUnlock.Call(hMem)

	if r1, _, callErr = procSetClipboardData.Call(cfUnicodeText, hMem); r1 == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("SetClipboardData falló: %v", callErr)
	}

	// Ownership transferred to clipboard.
	return nil
}
