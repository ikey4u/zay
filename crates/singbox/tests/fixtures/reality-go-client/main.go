//go:build with_utls

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

func main() {
	address := os.Getenv("SINGBOX_REALITY_RUST_SERVER")
	if address == "" {
		panic("SINGBOX_REALITY_RUST_SERVER is required")
	}
	publicKey := os.Getenv("SINGBOX_REALITY_PUBLIC_KEY")
	if publicKey == "" {
		panic("SINGBOX_REALITY_PUBLIC_KEY is required")
	}
	var options option.OutboundTLSOptions
	configJSON := fmt.Sprintf(`{
		"enabled": true,
		"server_name": "reality.example",
		"utls": {"enabled": true, "fingerprint": "chrome"},
		"reality": {
			"enabled": true,
			"public_key": %q,
			"short_id": "01020304"
		}
	}`, publicKey)
	if err := json.Unmarshal([]byte(configJSON), &options); err != nil {
		panic(err)
	}
	config, err := boxTLS.NewRealityClient(
		context.Background(), nil, address, options,
	)
	if err != nil {
		panic(err)
	}
	raw, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	connection, err := boxTLS.ClientHandshake(context.Background(), raw, config)
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte("go-reality-rust")); err != nil {
		panic(err)
	}
	response := make([]byte, len("go-reality-rust"))
	if _, err = io.ReadFull(connection, response); err != nil {
		panic(err)
	}
	if string(response) != "go-reality-rust" {
		panic(fmt.Sprintf("unexpected response %q", response))
	}
}
