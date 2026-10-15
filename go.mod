module github.com/mscno/esec-vault

go 1.27.0

require (
	github.com/alecthomas/kong v1.16.1
	github.com/fsnotify/fsnotify v1.10.1
	github.com/joho/godotenv v1.5.1
	github.com/mscno/esec v0.8.1 // needs v0.9.0 (branch feat/sealed-keyring): built through go.work until it is released
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/tyler-smith/go-bip39 v1.1.0
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/dustin/gojson v0.0.0-20160307161227-2e71ec9dd5ad // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.60.1 // indirect
)
