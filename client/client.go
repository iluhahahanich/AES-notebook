package main

// todo: auth with id, cypher, session_time, registration

import (
	"bufio"
	"bytes"
	"crypto/aes"
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
)

func main() {
	flag.StringVar(&serverAddr, "server-addr", "http://localhost:8080", "Address to reach server.")
	flag.Parse()

	for err := Login(); err != nil; err = Login() {
		fmt.Println(err, "\nTry again")
	}

	Process()
}

func Login() error {
	r := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	user, _ := r.ReadString('\n')
	user = strings.Trim(user, "\n\t ")

	fmt.Print("Password: ")
	password, _ := r.ReadString('\n')
	password = strings.Trim(password, "\n\t ")

	rsaPrivate, rsaPub := utils.GenerateKeyPair(2048)

	body := bytes.Buffer{}
	body.Write(utils.PublicKeyToBytes(rsaPub))

	req, err := http.NewRequest("GET", serverAddr+"/login", &body)
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
	body.Reset()
	io.Copy(&body, resp.Body)

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
		fmt.Print("Filename: ")
		file, _ := r.ReadString('\n')
		file = strings.Trim(file, "\n\t ")

		text, err := GetFile(file)
		if err != nil {
			fmt.Println("Failed to get a file:", err)
			continue
		}
		fmt.Println("File received: \n", text)
	}
}

func GetFile(file string) (string, error) {
	resp, err := http.Get(serverAddr + "/note?name=" + file)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	text, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ciph, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", err
	}
	dec := make([]byte, len(text))
	ciph.Decrypt(dec, text)
	return string(dec), nil
}
