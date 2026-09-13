//go:build with_quic

package main

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/network"
)

func main() {
	port, err := strconv.ParseUint(requiredEnv("SINGBOX_NAIVE_GO_PORT"), 10, 16)
	must(err)
	certificate := requiredEnv("SINGBOX_NAIVE_GO_CERTIFICATE")
	key := requiredEnv("SINGBOX_NAIVE_GO_KEY")

	options := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen: common.Ptr(
						badoption.Addr(netip.MustParseAddr("127.0.0.1")),
					),
					ListenPort: uint16(port),
				},
				Users: []auth.User{{
					Username: "alice",
					Password: "secret",
				}},
				Network: network.NetworkUDP,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      "naive.example.com",
						CertificatePath: certificate,
						KeyPath:         key,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance, err := box.New(box.Options{
		Context: include.Context(ctx),
		Options: options,
	})
	must(err)
	must(instance.Start())
	defer instance.Close()

	fmt.Printf("127.0.0.1:%d\n", port)
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(name + " is required")
	}
	return value
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
