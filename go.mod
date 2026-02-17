module autofirma-host

go 1.24.0

require (
	gioui.org v0.9.0
	github.com/beevik/etree v1.5.0
	github.com/digitorus/pdf v0.1.2
	github.com/digitorus/pdfsign v0.0.0-20260102145623-a2800162ff5c
	github.com/gorilla/websocket v1.5.3
	github.com/miekg/pkcs11 v1.1.1
	github.com/russellhaering/goxmldsig v1.5.0
	golang.org/x/sys v0.39.0
)

require (
	gioui.org/shader v1.0.8 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352 // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/go-text/typesetting v0.3.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattetti/filebuffer v1.0.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/exp/shiny v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/image v0.26.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/digitorus/pdfsign => ./third_party/pdfsign
