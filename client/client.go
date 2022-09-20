package main

// todo: cypher, session_time, registration, permissions?, place to keep rsa

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"../utils"
)

var (
	serverAddr string
	sessionKey []byte
	id         string
	rsaPrivate *rsa.PrivateKey
)

func main() {
	flag.StringVar(&serverAddr, "server-addr", "http://localhost:8080", "Address to reach server.")
	flag.Parse()

	for err := Login(); err != nil; err = Login() {
		fmt.Println(err, "\nTry again")
	}

	Process()
}

func ReadWithHint(r *bufio.Reader, hint string) string {
	fmt.Print(hint)
	line, _ := r.ReadString('\n')
	line = strings.Trim(line, "\n\t ")
	return line
}

func Login() error {
	r := bufio.NewReader(os.Stdin)

	user := ReadWithHint(r, "Username: ")
	password := ReadWithHint(r, "Password: ")

	rsaPrivate, _ = utils.GenerateKeyPair(2048)

	body := bytes.NewBuffer(utils.PublicKeyToBytes(&rsaPrivate.PublicKey))

	req, err := http.NewRequest("GET", serverAddr+"/login", body)
	if err != nil {
		return err
	}
	req.Header.Add("Username", user)
	req.Header.Add("Password", password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	id = resp.Header.Get("Id")
	body.Reset()
	io.Copy(body, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(body.String())
	}

	log.Println("authorized")
	sessionKey = utils.DecryptWithPrivateKey(body.Bytes(), rsaPrivate)
	fmt.Println("Session Key: ", sessionKey)

	return nil
}

func Process() {
	r := bufio.NewReader(os.Stdin)
	for {
		file := ReadWithHint(r, "Filename: ")

		text, err := GetFile(file)
		if err != nil {
			fmt.Println("Failed to get a file:", err)
			continue
		}
		fmt.Println("File received: \n", text)
	}
}

func GetFile(file string) (string, error) {
	req, err := http.NewRequest("GET", serverAddr+"/note?name="+file, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Id", id)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	text, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(string(text))
	}

	ciph, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", err
	}
	dec := make([]byte, len(text))
	ciph.Decrypt(dec, text)

	return string(dec), nil
}
