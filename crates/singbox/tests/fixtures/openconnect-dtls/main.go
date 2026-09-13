package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func putUint48(output []byte, value uint64) {
	output[0] = byte(value >> 40)
	output[1] = byte(value >> 32)
	output[2] = byte(value >> 24)
	output[3] = byte(value >> 16)
	output[4] = byte(value >> 8)
	output[5] = byte(value)
}

func deterministicRecord() []byte {
	const sequence = uint64(0x010203040506)
	payload := []byte("an IP packet")
	macHeader := make([]byte, 13)
	macHeader[1] = 1
	putUint48(macHeader[2:8], sequence)
	macHeader[8] = 23
	macHeader[9] = 1
	macHeader[11] = byte(len(payload) >> 8)
	macHeader[12] = byte(len(payload))
	mac := hmac.New(sha1.New, makeBytes(0x22, 20))
	mac.Write(macHeader)
	mac.Write(payload)
	plaintext := append(append([]byte(nil), payload...), mac.Sum(nil)...)
	paddingLength := aes.BlockSize - len(plaintext)%aes.BlockSize
	for range paddingLength {
		plaintext = append(plaintext, byte(paddingLength-1))
	}
	block, _ := aes.NewCipher(makeBytes(0x11, 16))
	iv := makeBytes(0x33, 16)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plaintext, plaintext)
	protected := append(iv, plaintext...)
	record := make([]byte, 13+len(protected))
	record[0] = 23
	record[1] = 1
	record[3] = 0
	record[4] = 1
	putUint48(record[5:11], sequence)
	record[11] = byte(len(protected) >> 8)
	record[12] = byte(len(protected))
	copy(record[13:], protected)
	return record
}

func makeBytes(value byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func pHash(secret, seed []byte, length int, newHash func() hash.Hash) []byte {
	result := make([]byte, 0, length)
	a := append([]byte(nil), seed...)
	for len(result) < length {
		advance := hmac.New(newHash, secret)
		advance.Write(a)
		a = advance.Sum(nil)
		round := hmac.New(newHash, secret)
		round.Write(a)
		round.Write(seed)
		result = append(result, round.Sum(nil)...)
	}
	return result[:length]
}

func tls10PRF(secret []byte, label string, seed []byte, length int) []byte {
	labeled := append(append([]byte(nil), []byte(label)...), seed...)
	half := (len(secret) + 1) / 2
	left := pHash(secret[:half], labeled, length, md5.New)
	right := pHash(secret[len(secret)-half:], labeled, length, sha1.New)
	for index := range left {
		left[index] ^= right[index]
	}
	return left
}

func tls12PRF(secret []byte, label string, seed []byte, length int, newHash func() hash.Hash) []byte {
	labeled := append(append([]byte(nil), []byte(label)...), seed...)
	return pHash(secret, labeled, length, newHash)
}

func deterministicDTLS12GCMRecord() []byte {
	const sequence = uint64(0x010203040506)
	const epoch = uint16(1)
	payload := []byte("an IP packet")
	recordNumber := make([]byte, 8)
	recordNumber[0] = byte(epoch >> 8)
	recordNumber[1] = byte(epoch)
	putUint48(recordNumber[2:], sequence)
	nonce := append(makeBytes(0x22, 4), recordNumber...)
	aad := make([]byte, 13)
	copy(aad[:8], recordNumber)
	aad[8] = 23
	aad[9] = 0xfe
	aad[10] = 0xfd
	aad[11] = byte(len(payload) >> 8)
	aad[12] = byte(len(payload))
	block, _ := aes.NewCipher(makeBytes(0x11, 16))
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(nil, nonce, payload, aad)
	protected := append(recordNumber, sealed...)
	record := make([]byte, 13+len(protected))
	record[0] = 23
	record[1] = 0xfe
	record[2] = 0xfd
	record[3] = byte(epoch >> 8)
	record[4] = byte(epoch)
	putUint48(record[5:11], sequence)
	record[11] = byte(len(protected) >> 8)
	record[12] = byte(len(protected))
	copy(record[13:], protected)
	return record
}

func pskPreMasterSecret(psk []byte) []byte {
	result := make([]byte, 2+len(psk)+2+len(psk))
	result[0] = byte(len(psk) >> 8)
	result[1] = byte(len(psk))
	offset := 2 + len(psk)
	result[offset] = byte(len(psk) >> 8)
	result[offset+1] = byte(len(psk))
	copy(result[offset+2:], psk)
	return result
}

func deterministicPSKClientHello() []byte {
	var randomBytes [handshake.RandomBytesLength]byte
	for index := range randomBytes {
		randomBytes[index] = 0x11
	}
	message := handshake.MessageClientHello{
		Version:   protocol.Version1_2,
		Random:    handshake.Random{GMTUnixTime: time.Unix(0x01020304, 0), RandomBytes: randomBytes},
		SessionID: []byte{0xaa, 0xbb},
		Cookie:    []byte{0x21, 0x22, 0x23},
		CipherSuiteIDs: []uint16{
			0xccab, 0x00a8, 0xc0a4, 0xc0a8, 0xc0a9, 0x00ae,
		},
		CompressionMethods: []*protocol.CompressionMethod{{}},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{SignatureHashAlgorithms: signaturehash.Algorithms()},
			&extension.RenegotiationInfo{RenegotiatedConnection: 0},
			&extension.UseExtendedMasterSecret{Supported: true},
		},
	}
	encoded, _ := message.Marshal()
	return encoded
}

func main() {
	fmt.Println(hex.EncodeToString(tls10PRF(
		[]byte("secret"), "test label", []byte("seed"), 48,
	)))
	fmt.Println(hex.EncodeToString(deterministicRecord()))
	fmt.Println(hex.EncodeToString(tls12PRF(
		[]byte("secret"), "test label", []byte("seed"), 48, sha256.New,
	)))
	fmt.Println(hex.EncodeToString(tls12PRF(
		[]byte("secret"), "test label", []byte("seed"), 64, sha512.New384,
	)))
	fmt.Println(hex.EncodeToString(deterministicDTLS12GCMRecord()))
	preMaster := pskPreMasterSecret([]byte("openconnect-psk"))
	fmt.Println(hex.EncodeToString(preMaster))
	clientRandom := makeBytes(0x11, 32)
	serverRandom := makeBytes(0x22, 32)
	standardSeed := append(append([]byte(nil), clientRandom...), serverRandom...)
	fmt.Println(hex.EncodeToString(tls12PRF(preMaster, "master secret", standardSeed, 48, sha256.New)))
	sessionHash := sha256.Sum256([]byte("client/server handshake transcript"))
	fmt.Println(hex.EncodeToString(tls12PRF(preMaster, "extended master secret", sessionHash[:], 48, sha256.New)))
	fmt.Println(hex.EncodeToString(deterministicPSKClientHello()))
}
