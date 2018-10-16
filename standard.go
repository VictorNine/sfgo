package sfgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

type Items struct {
	RetrievedItems []Item  `json:"retrieved_items"`
	SavedItems     []Item  `json:"saved_items"`
	Unsaved        []Item  `json:"unsaved"`
	SyncToken      string  `json:"sync_token"`
	CursorToken    *string `json:"cursor_token"`
}

type Item struct {
	UUID        string  `json:"uuid"`
	Content     string  `json:"content"`
	ContentType string  `json:"content_type"`
	EncItemKey  string  `json:"enc_item_key"`
	AuthHash    *string `json:"auth_hash"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	Deleted     bool    `json:"deleted"`
	PlanText    []byte  `json:"-"`
}

type syncReply struct {
	Items       []Item  `json:"items"`
	SyncToken   *string `json:"sync_token"`
	Limit       int     `json:"limit"`
	CursorToken *string `json:"cursor_token"`
}

// UpdateItem Put item in que to be synced
func (sess *Session) UpdateItem(item Item) error {
	sess.AddedItems = append(sess.AddedItems, item)

	return nil
}

// EncryptItem Encrypt an item with existing EncItemKey
func (sess *Session) EncryptItem(item *Item) error {
	if len(item.EncItemKey) < 1 {
		return errors.New("Item did not contain EncItemKey")
	}

	sess.generateContent(item)

	return nil
}

// NewItem Create new item
func (sess *Session) NewItem(plainText []byte, contentType string) error {
	uid, err := uuid.NewV4()
	if err != nil {
		return err
	}

	item := Item{
		UUID:        uid.String(),
		ContentType: contentType,
		CreatedAt:   time.Now().String(),
		UpdatedAt:   time.Now().String(),
		Deleted:     false,
		PlanText:    plainText,
	}

	err = sess.generateEncItemKey(&item)
	if err != nil {
		return err
	}
	err = sess.generateContent(&item)
	if err != nil {
		return err
	}

	sess.AddedItems = append(sess.AddedItems, item)

	return nil
}

// NewSession create a new session
func NewSession(URL string, email string) *Session {
	return &Session{
		URL:        URL,
		Email:      email,
		AddedItems: make([]Item, 0),
	}
}

// Sync Sync with server
func (sess *Session) Sync() (Items, error) {
	r := syncReply{
		SyncToken: sess.SyncToken,
		Limit:     150,
		Items:     sess.AddedItems,
	}

	jsonStr, err := json.Marshal(&r)
	if err != nil {
		return Items{}, err
	}

	sess.AddedItems = make([]Item, 0) // Items should now be synced. Delete them

	req, err := http.NewRequest("POST", sess.URL+"/items/sync", bytes.NewBuffer(jsonStr))
	if err != nil {
		return Items{}, err
	}
	req.Header.Add("Authorization", "Bearer "+sess.JWT)
	req.Header.Add("Content-type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Items{}, err
	}

	var items Items
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&items)
	if err != nil {
		return Items{}, err
	}

	// For some reason a newline is added to this. Remove it
	stoken := strings.TrimRight(items.SyncToken, "\n")
	sess.SyncToken = &stoken // Update sync token

	return items, nil
}

type Session struct {
	Email      string
	JWT        string
	URL        string
	SyncToken  *string
	Auth       AuthParmas
	AddedItems []Item // List off items that has not been synced
}

type AuthParmas struct {
	Identifier string  `json:"identifier"`
	PwSalt     *string `json:"pw_salt"`
	PwCost     int     `json:"pw_cost"`
	PwNonce    string  `json:"pw_nonce"`
	Version    string  `json:"version"`
	PW         string  `json:"-"`
	MK         string  `json:"-"`
	AK         string  `json:"-"`
}
