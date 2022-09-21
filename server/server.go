package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"time"

	"../crypto"
)

var (
	port     string
	usersDao *Dao

	storage  = make(map[string]struct{})
	sessions = make(map[UserID]session)
)

type session struct {
	user       string
	expiration time.Time
	sessionKey []byte
	rsaPub     *rsa.PublicKey
}

func main() {
	var err error
	usersDao, err = CreateDao(context.Background(), "server.db")
	if err != nil {
		fmt.Println("failed to load database:", err)
		return
	}

	flag.StringVar(&port, "port", "8080", "Port to run on")
	flag.Parse()

	if err := IndexStorage(); err != nil {
		fmt.Println("failed to index storage:", err)
		return
	}

	http.HandleFunc("/login", HandleLogin)
	http.HandleFunc("/file/", HandleFile)

	http.ListenAndServe(":"+port, nil)
}

func IndexStorage() error {
	files, err := ioutil.ReadDir("data")
	if err != nil {
		return err
	}

	for _, file := range files {
		storage[file.Name()] = struct{}{}
	}
	return nil
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	hdr := r.Header

	username, ok := hdr["Username"]
	if !ok {
		http.Error(w, "no username in header", http.StatusBadRequest)
		return
	}

	password, ok := hdr["Password"]
	if !ok {
		http.Error(w, "no password in header", http.StatusBadRequest)
		return
	}

	user, err := usersDao.Lookup(context.Background(), username[0])
	if err != nil {
		http.Error(w, "no such user "+username[0], http.StatusBadRequest)
		return
	}

	if user.Password != password[0] {
		http.Error(w, "password is incorrect", http.StatusUnauthorized)
		return
	}

	rsaPubStr := new(bytes.Buffer)
	io.Copy(rsaPubStr, r.Body)

	s := session{
		user:       user.Name,
		expiration: time.Now().Add(time.Minute),
		rsaPub:     crypto.StringToPublicKey(rsaPubStr.String()),
		sessionKey: make([]byte, 16),
	}
	rand.Read(s.sessionKey)
	sessions[user.ID] = s

	w.Header().Add("Id", fmt.Sprint(user.ID))
	w.Write(crypto.EncryptWithPublicKey(s.sessionKey, s.rsaPub))
	w.WriteHeader(http.StatusOK)

	return
}

func HandleFile(w http.ResponseWriter, r *http.Request) {
	idStr, ok := r.Header["Id"]
	if !ok {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	file, ok := r.URL.Query()["name"]
	if _, ok := storage[file[0]]; !ok {
		http.Error(w, "file "+file[0]+" not found", http.StatusBadRequest)
		return
	}

	sessionKey := sessions[ToID(idStr[0])].sessionKey

	cipher, err := crypto.NewAES(sessionKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, _ := os.Open("data/" + file[0])
	data, _ := io.ReadAll(f)
	enc := cipher.EncryptOFB(data, sessionKey)
	fmt.Fprint(w, string(enc))
}
