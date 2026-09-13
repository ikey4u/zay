package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/all"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const payloadSize = 2 * 1024 * 1024

func main() {
	server := M.ParseSocksaddr(requiredEnv("SINGBOX_NAIVE_RUST_SERVER"))
	target := M.ParseSocksaddr(requiredEnv("SINGBOX_NAIVE_TARGET"))
	certificate, err := os.ReadFile(requiredEnv("SINGBOX_NAIVE_CA"))
	must(err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		Context:                 ctx,
		ServerAddress:           server,
		ServerName:              "naive.example.com",
		Username:                "alice",
		Password:                "secret",
		TrustedRootCertificates: string(certificate),
		DNSResolver: func(_ context.Context, request *dns.Msg) *dns.Msg {
			response := new(dns.Msg)
			response.SetReply(request)
			return response
		},
		Logger:                logger.NOP(),
		QUIC:                  true,
		QUICCongestionControl: cronet.QUICCongestionControlBBRv2,
	})
	must(err)
	must(client.Start())
	defer client.Close()

	if netLog := os.Getenv("SINGBOX_NAIVE_NETLOG"); netLog != "" {
		if !client.Engine().StartNetLogToFile(netLog, false) {
			panic("start Cronet NetLog")
		}
		defer client.Engine().StopNetLog()
	}

	connection, err := client.DialContext(ctx, "tcp", target)
	must(err)
	defer connection.Close()

	payload := make([]byte, payloadSize)
	for index := range payload {
		payload[index] = byte(index*31 + 7)
	}
	must(connection.SetDeadline(time.Now().Add(25 * time.Second)))
	_, err = io.Copy(connection, bytes.NewReader(payload))
	must(err)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(connection, received)
	must(err)
	if !bytes.Equal(received, payload) {
		panic("Naive response payload mismatch")
	}
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(fmt.Sprintf("%s is required", name))
	}
	return value
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
