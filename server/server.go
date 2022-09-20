package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"time"

	"../utils"
)

var (
	port     string
	usersDao *utils.Dao

	storage  = make(map[string]struct{})
	sessions = make(map[utils.UserID]session)
)

type session struct {
	user       string
	expiration time.Time
	sessionKey []byte
	rsaKey     *rsa.PublicKey
}

func main() {
	var err error
	usersDao, err = utils.CreateDao(context.Background(), "server.db")
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
	http.HandleFunc("/note/", HandleNote)

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
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		rsaKey:     utils.StringToPublicKey(rsaPubStr.String()),
		sessionKey: make([]byte, 16),
	}
	rand.Read(s.sessionKey)
	sessions[user.ID] = s

	w.Header().Add("Id", fmt.Sprint(user.ID))
	w.Write(utils.EncryptWithPublicKey(s.sessionKey, s.rsaKey))
	w.WriteHeader(http.StatusOK)
	return
}

func HandleNote(w http.ResponseWriter, r *http.Request) {
	idStr, ok := r.Header["Id"]
	if !ok {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	file := r.URL.Query().Get("name")
	if _, ok := storage[file]; !ok {
		http.Error(w, "file "+file+" not found", http.StatusBadRequest)
		return
	}

	sessionKey := sessions[utils.ToID(idStr[0])].sessionKey

	ciph, err := aes.NewCipher(sessionKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, _ := os.Open("data/" + file)
	data, _ := io.ReadAll(f)
	enc := make([]byte, len(data))
	ciph.Encrypt(enc, data)
	fmt.Fprintln(w, string(enc))
}
