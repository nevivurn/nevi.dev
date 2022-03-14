package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
)

func main() {
	c, err := net.Dial("udp", "3.93.213.98:9855")
	if err != nil {
		panic(err)
	}
	defer c.Close()

	buf := bytes.Buffer{}
	buf.Write(make([]byte, 12))
	buf.WriteByte(byte(len("publickey")))
	buf.WriteString("publickey")
	buf.Write(make([]byte, 5))
	buf.WriteByte(0)

	if _, err := c.Write(buf.Bytes()); err != nil {
		panic(err)
	}

	rbuf := make([]byte, 65536)

	n, err := c.Read(rbuf)
	if err != nil {
		panic(err)
	}
	out := readMessage(rbuf[:n], buf.Len())

	block, _ := pem.Decode(out)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPub := pub.(*rsa.PublicKey)

	msg := "cat flag.txt"
	enc, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, rsaPub, []byte(msg), nil)
	if err != nil {
		panic(err)
	}

	buf.Reset()
	buf.Write(make([]byte, 12))

	for len(enc) > 0 {
		cur := len(enc)
		if cur > 255 {
			cur = 255
		}
		buf.WriteByte(byte(cur))
		buf.Write(enc[:cur])
		enc = enc[cur:]
		buf.Write(make([]byte, 5))
	}
	buf.WriteByte(0)

	if _, err := c.Write(buf.Bytes()); err != nil {
		panic(err)
	}

	n, err = c.Read(rbuf)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(readMessage(rbuf[:n], buf.Len())))
}

func readMessage(b []byte, reqLen int) []byte {
	responses, b := int(b[7]), b[reqLen-1:]

	var out []byte
	for i := 0; i < responses; i++ {
		rlen := int(b[12])
		b = b[13:]

		out, b = append(out, b[:rlen]...), b[rlen:]
	}

	return out
}
