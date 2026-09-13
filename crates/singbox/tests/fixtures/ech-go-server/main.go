package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"time"

	singboxtls "github.com/sagernet/sing-box/common/tls"
)

func main() {
	rawKey, err := base64.StdEncoding.DecodeString(os.Getenv("SINGBOX_ECH_KEY"))
	check(err)
	block, rest := pem.Decode(rawKey)
	if block == nil || block.Type != "ECH KEYS" || len(rest) != 0 {
		panic("invalid ECH key PEM")
	}
	echKeys, err := singboxtls.UnmarshalECHKeys(block.Bytes)
	check(err)
	if os.Getenv("SINGBOX_ECH_SEND_RETRY") == "1" {
		for index := range echKeys {
			echKeys[index].SendAsRetry = true
		}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "secret.example"},
		DNSNames:     []string{"secret.example"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &privateKey.PublicKey, privateKey,
	)
	check(err)
	certificate := tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  privateKey,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:             []tls.Certificate{certificate},
		EncryptedClientHelloKeys: echKeys,
		MinVersion:               tls.VersionTLS13,
	})
	check(err)
	defer listener.Close()
	fmt.Println(listener.Addr().String())

	accepts := 1
	if rawAccepts := os.Getenv("SINGBOX_ECH_ACCEPTS"); rawAccepts != "" {
		accepts, err = strconv.Atoi(rawAccepts)
		check(err)
	}
	for index := 0; index < accepts; index++ {
		connection, err := listener.Accept()
		check(err)
		_, copyErr := io.Copy(connection, connection)
		connection.Close()
		if index+1 == accepts {
			check(copyErr)
		}
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
