package tepassword

import "testing"

func TestCreatePasswordHash(t *testing.T) {
	_, err := CreatePasswordHash("test123")

	if err != nil {
		t.Errorf("Got error message: %s", err.Error())
	}
}

func TestCheckPassword(t *testing.T) {

	passwordHash, _ := CreatePasswordHash("test")
	correctPassword, err := CheckPassword("test", passwordHash)

	if err != nil {
		t.Errorf("Got error message: %s", err.Error())
	}


	if !correctPassword {
		t.Errorf("Returns a don't match, but they should match.")
	}
}

func TestCheckPassword2(t *testing.T) {
	passwordHash, _ := CreatePasswordHash("test")
	correctPassword, err := CheckPassword("test123", passwordHash)

	if err != nil {
		t.Errorf("Got error message: %s", err.Error())
	}

	if correctPassword {
		t.Errorf("Return a match, but they should not match this time.")
	}

}