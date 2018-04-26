// Wrapper library for hashing and check password against hash
package tepassword

import (
	"crypto/rand"
	"log"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
)

// This function generates the pbkdf2 hash from the password
// the user specifies. It will generate a random salt for the
// password hash.
func CreatePasswordHash(password string) (string, error) {
	// Generates 16bytes of random data
	salt := make([]byte, 16)
	if _, err := rand.Reader.Read(salt); err != nil {
		log.Println("Random reader failed")
		return "", err
	}

	return generateHash(password, salt)
}

func generateHash(password string, salt []byte) (string, error) {

	// Generates the password hash
	passwordHash := pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)

	// Builds how the hash should look like
	pbHash := fmt.Sprintf("pbkdf2:sha256:4096:%x$%x", salt, passwordHash)

	// Returns the pbkdf2 hash
	return pbHash, nil
}

// This function will check if the password is the correct password for the
// hash supplied as the second argument.
func CheckPassword(password string, pbHash string) (isValid bool, err error) {

	// Initiates variables
	var salt []byte
	var passwordHash string

	// Retrieves the password hash and salt from the pbHash
	fmt.Sscanf(pbHash, "pbkdf2:sha256:4096:%32x$%64s", &salt, &passwordHash)

	// Generates the hash with the users password
	userPasswordHash, err := generateHash(password, salt)

	// Checks if there were any errors generating the hash
	if err != nil {
		return false, err
	}

	// If the password match, return true
	if userPasswordHash == pbHash {
		return true, nil
	}

	// Return false on everything else
	return false, nil
}

func main() {

	pbHash,_ := CreatePasswordHash("hejsan")

	authorized, _ := CheckPassword("hejsan", pbHash)

	if authorized {
		fmt.Println("Welcome good sir")
	} else {
		fmt.Println("GTFO")
	}

}
