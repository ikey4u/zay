package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	boxLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func main() {
	address := os.Getenv("SINGBOX_ECH_RUST_SERVER")
	if address == "" {
		panic("SINGBOX_ECH_RUST_SERVER is required")
	}
	configPEM, err := base64.StdEncoding.DecodeString(
		os.Getenv("SINGBOX_ECH_CONFIG"),
	)
	check(err)

	var options option.OutboundTLSOptions
	configJSON := fmt.Sprintf(`{
		"enabled": true,
		"server_name": "secret.example",
		"insecure": true,
		"ech": {"enabled": true, "config": [%q]}
	}`, string(configPEM))
	check(json.Unmarshal([]byte(configJSON), &options))
	config, err := boxTLS.NewClient(
		context.Background(),
		boxLog.NewNOPFactory().Logger(),
		"secret.example",
		options,
	)
	check(err)
	raw, err := net.Dial("tcp", address)
	check(err)
	connection, err := boxTLS.ClientHandshake(
		context.Background(),
		raw,
		config,
	)
	check(err)
	defer connection.Close()

	const payload = "go-ech-rust"
	_, err = connection.Write([]byte(payload))
	check(err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(connection, response)
	check(err)
	if string(response) != payload {
		panic(fmt.Sprintf("unexpected response %q", response))
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
