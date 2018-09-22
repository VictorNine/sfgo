package sfgo

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// GetPasswordParams retrive password parmaeters from server
func (sess *Session) getPasswordParams() error {
	resp, err := http.Get(sess.URL + "/auth/params?email=" + sess.Email)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var pp AuthParmas
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&pp)
	if err != nil {
		return err
	}

	sess.Auth = pp

	return nil
}

// GenerateKeys generate login and encryption keys
func (sess *Session) GenerateKeys(password string) {
	h := sha256.New()
	CostString := strconv.Itoa(sess.Auth.PwCost)
	h.Write([]byte(sess.Email + ":SF:" + sess.Auth.Version + ":" + CostString + ":" + sess.Auth.PwNonce))
	salt := hex.EncodeToString(h.Sum(nil))

	key := hex.EncodeToString(pbkdf2.Key([]byte(password), []byte(salt), sess.Auth.PwCost, 96, sha512.New))

	sess.Auth.PW = key[0 : len(key)/3]
	sess.Auth.MK = key[len(key)/3 : (len(key)/3)*2]
	sess.Auth.AK = key[(len(key)/3)*2 : len(key)]

}

type token struct {
	Token  string
	Errors []string
}

// Signin Authenticates a user and returns a JWT.
func (sess *Session) Signin(pw string) error {
	err := sess.getPasswordParams()
	if err != nil {
		log.Fatal(err)
	}

	sess.GenerateKeys(pw)

	resp, err := http.PostForm(sess.URL+"/auth/sign_in",
		url.Values{"email": {sess.Email}, "password": {sess.Auth.PW}})
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var token token
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&token)
	if err != nil {
		return err
	}

	if token.Errors != nil {
		return errors.New("Unknown error")
	}

	sess.JWT = token.Token
	return nil
}
