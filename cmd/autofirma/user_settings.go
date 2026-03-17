package main

type UserSettings struct {
	ExpertMode       bool   `json:"expertMode"`
	ThemeIndex       int    `json:"themeIndex"`
	AutoClose        bool   `json:"autoClose"`
	StickySigner     bool   `json:"stickySigner"`
	CertsExpiredShow bool   `json:"certsExpiredShow"`
	TsaEnabled       bool   `json:"tsaEnabled"`
	TsaUrl           string `json:"tsaUrl"`
	ProxyEnabled     bool   `json:"proxyEnabled"`
	ProxyHost        string `json:"proxyHost"`
	ProxyPort        int    `json:"proxyPort"`
}
