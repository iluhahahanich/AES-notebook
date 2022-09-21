package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
)

func unwrap[T any](val T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return val
}

func assert(ok bool, msg string) {
	if !ok {
		log.Fatalf(msg)
	}
}

func GenerateKey(bits int) *rsa.PrivateKey {
	return unwrap(rsa.GenerateKey(rand.Reader, bits))
}

func PublicKeyToString(pub *rsa.PublicKey) string {
	return pub.N.String() + "\t" + fmt.Sprint(pub.E)
}

func StringToPublicKey(str string) *rsa.PublicKey {
	split := strings.SplitN(str, "\t", 2)
	assert(len(split) == 2, "wrong string format for pub key")

	n := new(big.Int)
	_, ok := n.SetString(split[0], 10)
	assert(ok, fmt.Sprintf("'%s' is not a number", split[0]))

	e := unwrap(strconv.Atoi(split[1]))

	return &rsa.PublicKey{N: n, E: e}
}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	return unwrap(rsa.EncryptPKCS1v15(rand.Reader, pub, msg))
}

func DecryptWithPrivateKey(ciphertext []byte, privateKey *rsa.PrivateKey) []byte {
	return unwrap(rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext))
}
