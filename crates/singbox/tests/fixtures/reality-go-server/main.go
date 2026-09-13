//go:build with_utls

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

func main() {
	coverAddress := requiredEnvironment("SINGBOX_REALITY_COVER_SERVER")
	privateKey := requiredEnvironment("SINGBOX_REALITY_PRIVATE_KEY")
	coverHost, coverPortText, err := net.SplitHostPort(coverAddress)
	if err != nil {
		panic(err)
	}
	coverPort, err := strconv.ParseUint(coverPortText, 10, 16)
	if err != nil {
		panic(err)
	}

	var options option.InboundTLSOptions
	configJSON := fmt.Sprintf(`{
		"enabled": true,
		"server_name": "reality.example",
		"reality": {
			"enabled": true,
			"private_key": %q,
			"short_id": ["01020304"],
			"handshake": {
				"server": %q,
				"server_port": %d
			}
		}
	}`, privateKey, coverHost, coverPort)
	if err = json.Unmarshal([]byte(configJSON), &options); err != nil {
		panic(err)
	}
	ctx := context.Background()
	config, err := boxTLS.NewServer(ctx, nil, options)
	if err != nil {
		panic(err)
	}
	defer config.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println(listener.Addr())

	raw, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	connection, err := boxTLS.ServerHandshake(
		context.Background(), raw, config,
	)
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	payload := make([]byte, len("rust-reality-go"))
	if _, err = io.ReadFull(connection, payload); err != nil {
		panic(err)
	}
	if string(payload) != "rust-reality-go" {
		panic(fmt.Sprintf("unexpected request %q", payload))
	}
	if _, err = connection.Write(payload); err != nil {
		panic(err)
	}
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(name + " is required")
	}
	return value
}
