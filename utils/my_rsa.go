package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
)

func Unwrap[T any](val T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return val
}

func Assert(ok bool, msg string) {
	if !ok {
		log.Fatalf(msg)
	}
}

func GenerateKey(bits int) *rsa.PrivateKey {
	return Unwrap(rsa.GenerateKey(rand.Reader, bits))
}

func PublicKeyToString(pub *rsa.PublicKey) string {
	return pub.N.String() + "\t" + fmt.Sprint(pub.E)
}

func StringToPublicKey(str string) *rsa.PublicKey {
	split := strings.SplitN(str, "\t", 2)
	Assert(len(split) == 2, "wrong string format for pub key")

	n := new(big.Int)
	_, ok := n.SetString(split[0], 10)
	Assert(ok, fmt.Sprintf("'%s' is not a number", split[0]))

	e := Unwrap(strconv.Atoi(split[1]))

	return &rsa.PublicKey{N: n, E: e}
}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	return Unwrap(rsa.EncryptPKCS1v15(rand.Reader, pub, msg))
}

func DecryptWithPrivateKey(ciphertext []byte, privateKey *rsa.PrivateKey) []byte {
	return Unwrap(rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext))
}
