package sfgo

import (
	"testing"
	"time"
)

func TestGetHMACH(t *testing.T) {
	hmac, err := getHMAC("33333333-a239-33a3-3a3a-33333aa3aa33", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "testdatatestdata", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	if err != nil {
		t.Errorf("Got error %s\n", err)
	}
	if hmac != "02ef598ff0d0ef4221d43882a361d50b355d4906a7c406b69bdd0cfb13319be3" {
		t.Errorf("Wrong hmac, got %s\n", hmac)
	}
}

// TODO: Split into more tests
func TestEncDec(t *testing.T) {
	sess := Session{
		Email: "test@test.com",
		Auth: AuthParmas{
			Identifier: "test@test.com",
			PwCost:     110000,
			PwNonce:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Version:    "003",
			MK:         "0000000000000000000000000000000000000000000000000000000000000000",
			AK:         "1111111111111111111111111111111111111111111111111111111111111111",
		},
	}

	myitem := Item{
		UUID:        "00000000-a000-00a0-0a00-00a0aaa0aa00",
		ContentType: "Note",
		CreatedAt:   time.Now().String(),
		UpdatedAt:   time.Now().String(),
		Deleted:     false,
		PlanText:    []byte("TestTest"),
	}

	sess.generateEncItemKey(&myitem)
	sess.generateContent(&myitem)

	plaintext, _ := sess.Decrypt(&myitem)
	if string(plaintext) != "TestTest" {
		t.Error("Wrong output")
	}

}
