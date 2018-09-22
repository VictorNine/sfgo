package sfgo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// ### Encryption ####

func (sess *Session) generateEncItemKey(item *Item) error {
	itemKey := make([]byte, 64) // 512 bit key
	_, err := rand.Read(itemKey)
	if err != nil {
		return err
	}

	itemKeyS := hex.EncodeToString(itemKey)
	cipherText, iv, err := sess.encrypt([]byte(itemKeyS), []byte(sess.Auth.MK))
	if err != nil {
		return err
	}

	ivs := hex.EncodeToString(iv)

	hmac, err := getHMAC(item.UUID, ivs, cipherText, string(sess.Auth.AK))
	if err != nil {
		return err
	}

	authParams, err := json.Marshal(&sess.Auth)
	if err != nil {
		return err
	}

	item.EncItemKey = "003:" + hmac + ":" + item.UUID + ":" + ivs + ":" + cipherText + ":" + b64.StdEncoding.EncodeToString(authParams)

	return nil
}

func (sess *Session) generateContent(item *Item) error {
	// Get the encryption keys
	itemMK, itemAK, err := sess.getEncItemKey(item.EncItemKey)
	if err != nil {
		return err
	}

	// Encrypt PlainText
	cipherText, iv, err := sess.encrypt([]byte(item.PlanText), itemMK)
	if err != nil {
		return err
	}
	ivs := hex.EncodeToString(iv)

	hmac, err := getHMAC(item.UUID, ivs, cipherText, string(itemAK))
	if err != nil {
		return err
	}

	authParams, err := json.Marshal(&sess.Auth)
	if err != nil {
		return err
	}

	item.Content = "003:" + hmac + ":" + item.UUID + ":" + ivs + ":" + cipherText + ":" + b64.StdEncoding.EncodeToString(authParams)

	return nil
}

func (sess *Session) encrypt(plainText []byte, itemMK []byte) (string, []byte, error) {
	key, err := hex.DecodeString(string(itemMK))
	if err != nil {
		return "", nil, err
	}

	// Gerenate 128 bit IV
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return "", nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}

	b, err := pkcs7Pad(plainText, aes.BlockSize)
	if err != nil {
		return "", nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(b, b)

	return b64.StdEncoding.EncodeToString(b), iv, nil
}

// ### Decryption ####

// Generate encryption and authentication keys from encItemKey
func (sess *Session) getEncItemKey(encItemKey string) ([]byte, []byte, error) {
	keyData, err := splitData(encItemKey)
	if err != nil {
		return nil, nil, err
	}
	keyData.MK = sess.Auth.MK
	keyData.AK = sess.Auth.AK
	key, err := keyData.decrypt()
	if err != nil {
		return nil, nil, err
	}

	// Split the key
	itemMK := key[0:64]
	itemAK := key[64:128]

	return itemMK, itemAK, nil
}

// Decrypt decrypt an item
func (sess *Session) Decrypt(item *Item) ([]byte, error) {
	if item.Deleted {
		return nil, errors.New("Nothing to decrypt")
	}

	MK, AK, err := sess.getEncItemKey(item.EncItemKey)
	if err != nil {
		return nil, err
	}

	data, err := splitData(item.Content)
	if err != nil {
		return nil, err
	}
	data.MK = string(MK)
	data.AK = string(AK)
	data.UUID = item.UUID

	plainText, err := data.decrypt()

	return plainText, err
}

type data struct {
	version    string
	UUID       string
	cipherText string
	iv         string
	AK         string
	MK         string
	AuthHash   string
}

func (data *data) decrypt() ([]byte, error) {
	// Auth
	hmac, err := getHMAC(data.UUID, data.iv, data.cipherText, data.AK)
	if err != nil {
		return nil, err
	}
	if hmac != data.AuthHash {
		return nil, errors.New("Wrong hash")
	}

	// Decrypt
	key, err := hex.DecodeString(data.MK)
	if err != nil {
		return nil, err
	}

	ciphertext, err := b64.StdEncoding.DecodeString(data.cipherText)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(data.iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	ciphertext, err = pkcs7Unpad(ciphertext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func splitData(str string) (data, error) {
	components := strings.Split(str, ":")
	if len(components) < 5 {
		return data{}, errors.New("Not enough components")
	}
	data := data{
		version:    components[0],
		AuthHash:   components[1],
		UUID:       components[2],
		iv:         components[3],
		cipherText: components[4],
	}

	return data, nil
}

func getHMAC(UUID, IV, cipherText, AK string) (string, error) {
	stringToAuth := "003:" + UUID + ":" + IV + ":" + cipherText
	key, err := hex.DecodeString(AK)
	if err != nil {
		return "", nil
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(stringToAuth))

	return hex.EncodeToString(h.Sum(nil)), nil
}
