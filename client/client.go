package main

// ECDSA instead of RSA ------- if need to implement rsa
// registration ------- only with editing, deleting and etc

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"errors"
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
	id         string
	rsaPrivate *rsa.PrivateKey
	sessionKey []byte
)

var ExpiredErr = errors.New("session expired")

func main() {
	flag.StringVar(&serverAddr, "server-addr",
		"http://localhost:8080", "Address to reach server.")
	flag.Parse()

	r := bufio.NewReader(os.Stdin)

	rsaPrivate = crypto.GenerateKey(2048)

login:
	err := login(r)
	if err != nil {
		fmt.Println(err, "\nTry again")
		goto login
	}

process:
	switch err = process(r); err {
	case ExpiredErr:
		fmt.Println(ExpiredErr)
		goto login
	case nil:
		goto process
	default:
		fmt.Println("failed to get file: " + err.Error())
		goto process
	}
}

func readWithHint(r *bufio.Reader, hint string) string {
	fmt.Print(hint)
	line, _ := r.ReadString('\n')
	line = strings.Trim(line, "\n\t ")
	return line
}

func login(r *bufio.Reader) error {
	user := readWithHint(r, "Username: ")
	password := readWithHint(r, "Password: ")

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
	if _, err = io.Copy(body, resp.Body); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(body.String())
	}

	log.Println("authorized")
	sessionKey = crypto.DecryptWithPrivateKey(body.Bytes(), rsaPrivate)

	return nil
}

func process(r *bufio.Reader) error {
	str := readWithHint(r, "Type '\\gen' to regen RSA Key or filename: ")
	if str == "\\gen" {
		return regenRSA()
	}

	text, err := getFile(str)
	if err != nil {
		return err
	}

	fmt.Println("Data: ")
	fmt.Println(text)

	return nil
}

func regenRSA() error {
	rsaPrivate = crypto.GenerateKey(2048)

	body := bytes.NewBufferString(crypto.PublicKeyToString(&rsaPrivate.PublicKey))

	req, err := http.NewRequest("GET", serverAddr+"/regen", body)
	if err != nil {
		return err
	}
	req.Header.Add("Id", id)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body.Reset()
	if _, err = io.Copy(body, resp.Body); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(body.String())
	}

	fmt.Println("RSA generated successfully")
	return nil
}

func getFile(file string) (string, error) {
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

	if _, ok := resp.Header["Expired"]; ok {
		return "", ExpiredErr
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(string(text))
	}

	cipher, err := crypto.NewAES(sessionKey[:16])
	if err != nil {
		return "", err
	}

	dec := cipher.DecryptOFB(text, sessionKey[16:])

	return string(dec), nil
}
