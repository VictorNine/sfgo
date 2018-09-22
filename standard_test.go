package sfgo

import "testing"

func TestGenerateKeys(t *testing.T) {
	sess := Session{
		Email: "test@test.com",
		Auth: AuthParmas{
			PwNonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Version: "003",
			PwCost:  110000,
		},
	}
	sess.GenerateKeys("testtest")

	if sess.Auth.PW != "c243300198e654f0f777586850657df158dde21db8483f4544cd636430d682f2" {
		t.Errorf("Wrong PW, got %s", sess.Auth.PW)
	}
	if sess.Auth.MK != "6530ac20276b4de583a9da555a528f13248ce3df00b579a719f032cfe6ff1b23" {
		t.Errorf("Wrong MK, got %s", sess.Auth.MK)
	}
	if sess.Auth.AK != "126dfbd0eb8266e20a4a9d56f828d54d6317d84cccab3ec2696fa962305553b4" {
		t.Errorf("Wrong AK, got %s", sess.Auth.AK)
	}
}
