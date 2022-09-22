package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"../crypto"
)

var (
	port     string
	err      error
	usersDao *Dao

	kSessionTime = 20 * time.Second

	storage  = make(map[string]struct{})
	sessions = make(map[UserID]session)
	m        = sync.RWMutex{}
)

type session struct {
	user       string
	sessionKey []byte
	rsaPub     *rsa.PublicKey
	expireTime time.Time
}

func main() {
	flag.StringVar(&port, "port", "8080", "Port to run on")
	flag.Parse()

	usersDao, err = CreateDao(context.Background(), "server.db")
	assert(err, "failed to connect database:")

	err = indexStorage()
	assert(err, "failed to index storage:")

	http.HandleFunc("/regen", handleRegen)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/file/", handleFile)

	err = http.ListenAndServe(":"+port, nil)
	assert(err, "failed to create a server:")
}

func assert(err error, msg string) {
	if err != nil {
		log.Fatal(msg, err)
	}
}

func indexStorage() error {
	files, err := ioutil.ReadDir("data")
	if err != nil {
		return err
	}

	for _, file := range files {
		storage[file.Name()] = struct{}{}
	}
	return nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
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
	_, err = io.Copy(rsaPubStr, r.Body)
	if err != nil {
		http.Error(w, "error while reading request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	m.Lock()
	s := session{
		user:       user.Name,
		expireTime: time.Now().Add(kSessionTime),
		rsaPub:     crypto.StringToPublicKey(rsaPubStr.String()),
		sessionKey: make([]byte, 32),
	}
	rand.Read(s.sessionKey)
	sessions[user.ID] = s
	m.Unlock()

	w.Header().Add("Id", fmt.Sprint(user.ID))
	_, err = w.Write(crypto.EncryptWithPublicKey(s.sessionKey, s.rsaPub))
	if err != nil {
		http.Error(w, "error while writing response body", http.StatusBadRequest)
		return
	}
	return
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	idStr, ok := r.Header["Id"]
	if !ok {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	file, ok := r.URL.Query()["name"]
	if !ok {
		http.Error(w, "file name required", http.StatusBadRequest)
		return
	}
	if _, ok := storage[file[0]]; !ok {
		http.Error(w, "file '"+file[0]+"' not found", http.StatusBadRequest)
		return
	}

	id := ToID(idStr[0])

	m.Lock()
	sess, ok := sessions[id]
	if !ok {
		http.Error(w, "please login into session", http.StatusBadRequest)
		m.Unlock()
		return
	}
	sessionKey := sess.sessionKey
	if sess.expireTime.Sub(time.Now()) <= 0 {
		w.Header().Add("Expired", "")
		w.WriteHeader(http.StatusOK)
		m.Unlock()
		return
	}
	m.Unlock()

	cipher, err := crypto.NewAES(sessionKey[:16])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, _ := os.Open("data/" + file[0])
	data, _ := io.ReadAll(f)
	enc := cipher.EncryptOFB(data, sessionKey[16:])
	if _, err = w.Write(enc); err != nil {
		http.Error(w, "error while writing file: "+err.Error(), http.StatusBadRequest)
		return
	}
}

func handleRegen(w http.ResponseWriter, r *http.Request) {
	idStr, ok := r.Header["Id"]
	if !ok {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	rsaPubStr := new(bytes.Buffer)
	_, err = io.Copy(rsaPubStr, r.Body)
	if err != nil {
		http.Error(w, "error while reading request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	id := ToID(idStr[0])

	m.Lock()
	s, ok := sessions[id]
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		m.Unlock()
		return
	}
	s.rsaPub = crypto.StringToPublicKey(rsaPubStr.String())
	sessions[id] = s
	m.Unlock()
}
