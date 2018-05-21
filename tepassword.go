// Wrapper library for hashing and check password against hash
package tepassword

import (
	"math/rand"
	"log"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
	"strings"
)


func generateRandomString(lenght int) (string, error) {

	// All the chars the salt could be generated from
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")

	// Initializes a rune array where we will store our chars
	buf := make([]rune, lenght)

	// Adds a random char to the array
	for i := range buf {
		buf[i] = chars[rand.Intn(len(chars))]
	}

	// Returns the array as a string and error set to nil
	return string(buf), nil
}

// This function generates the pbkdf2 hash from the password
// the user specifies. It will generate a random salt for the
// password hash.
func CreatePasswordHash(password string) (string, error) {
	// Generates 16bytes of random data
	salt, err := generateRandomString(10)
	if err != nil {
		log.Println("Random reader failed")
		return "", err
	}
	return generateHash(password, salt, 4096)
}

func generateHash(password string, salt string, iterations int) (string, error) {

	// Generates the password hash
	passwordHash := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)

	// Builds how the hash should look like
	pbHash := fmt.Sprintf("pbkdf2:sha256:%d$%s$%x", iterations, salt, passwordHash)

	// Returns the pbkdf2 hash
	return pbHash, nil
}

// This function will check if the password is the correct password for the
// hash supplied as the second argument.
func CheckPassword(password string, pbHash string) (isValid bool, err error) {

	// Initiates variables
	var salt string
	var iterations int
	var fullHash string

	// Retrieves the password hash and salt from the pbHash
	fmt.Sscanf(pbHash, "pbkdf2:sha256:%d$%s", &iterations, &fullHash)

	// Parse out the salt part of the hash
	salt = strings.Split(fullHash, "$")[0]

	// Generates the hash with the users password
	userPasswordHash, err := generateHash(password, salt, iterations)

	fmt.Println(userPasswordHash)

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
