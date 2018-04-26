package tepassword


import "testing"

func TestCreatePasswordHash(t *testing.T) {
	passwordHash, err := CreatePasswordHash("test123")

	if len(passwordHash) != 116 {
		t.Errorf("Password hash should be 116 chars, this has is %d", len(passwordHash))
	}

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