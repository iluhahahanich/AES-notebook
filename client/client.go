package main

// RSA by hand? Does rating matter
// todo: session_time, RSA Gen & Store
// ECDSA instead of RSA ------- if need to implement rsa
// registration ------- only with editing, deleting and etc

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"../crypto"
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

	rsaPrivate = crypto.GenerateKey(2048)

	body := bytes.NewBufferString(crypto.PublicKeyToString(&rsaPrivate.PublicKey))

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
	sessionKey = crypto.DecryptWithPrivateKey(body.Bytes(), rsaPrivate)

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
		fmt.Println("Data: ")
		fmt.Println(text)
	}
}

func GetFile(file string) (string, error) {
	req, err := http.NewRequest("GET", serverAddr+"/file/", nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = url.Values{"name": {file}}.Encode()
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

	cipher, err := crypto.NewAES(sessionKey)
	if err != nil {
		return "", err
	}
	dec := cipher.DecryptOFB(text, sessionKey)

	return string(dec), nil
}
