package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

var usage = `
elg-decrypt <filename of ciphertext> <filename to read secret key>.

Reads in the ciphertext produced by the previous program and a stored secret, prints
the recovered message or error.
`

func toDecInt(n *big.Int) string {
	return fmt.Sprintf("%d", n)
}

func decryptCiphertext(C string, k string) string {

	key, _ := hex.DecodeString(k)
	ciphertext, _ := hex.DecodeString(C)

	ciphertext = []byte(ciphertext)
	nonce := make([]byte, 12)
	copy(nonce, ciphertext[0:12])
	ciphertext = ciphertext[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error\n")
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error\n")
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("Error\n")
		panic(err.Error())
	}

	return string(plaintext)
}

func readCiphertextFromFile(name string) (string, *big.Int) {

	str, err := ioutil.ReadFile(name)
	if err != nil {
		fmt.Printf("%x\n", err)
	}
	s := string(str)

	// Strip out the "( " and the " )"
	s = strings.TrimLeft(s, "( ")
	s = strings.TrimRight(s, " )")

	// DH Params are stored as ( gb,k )
	params := strings.Split(s, ",")

	if len(params) != 2 {
		fmt.Printf("There should be atleast 2 parameters ( gb,k ) in the file %x\n", name)
		os.Exit(1)
	}
	gb, _ := new(big.Int).SetString(params[0], 10)
	ciphertext := params[1]

	return ciphertext, gb
}

func checkError(err error) {
	if err != nil {
		fmt.Printf("%x", err)
		os.Exit(1)
	}
}

// Returns public key (p, g, a)
func readSecretKeyFromFile(name string) (*big.Int, *big.Int, *big.Int) {
	str, err := ioutil.ReadFile(name)
	if err != nil {
		fmt.Printf("%x\n", err)
	}
	s := string(str)

	// Strip out the "( " and the " )"
	s = strings.TrimLeft(s, "( ")
	s = strings.TrimRight(s, " )")

	// DH Params are stored as ( p, g, ga )
	params := strings.Split(s, ",")

	if len(params) != 3 {
		fmt.Printf("There should be atleast 3 parameters ( p, g, a ) in the file %x\n", name)
		os.Exit(1)
	}

	// Hoping they unmarshal correctly - base is 10 since decimal
	p, _ := new(big.Int).SetString(params[0], 10)
	g, _ := new(big.Int).SetString(params[1], 10)
	a, _ := new(big.Int).SetString(params[2], 10)

	return p, g, a
}

// Returns Key k
func generateKey(p, g, gb, a *big.Int) string {

	// Compute k = SHA256(ga | gb | gab)
	ga := new(big.Int).Exp(g, a, p)
	gab := new(big.Int).Exp(gb, a, p)

	h := sha256.New()

	// For compatibility, please encode your input to SHA256 using decimal formatted integers separated by a single space character.
	val := toDecInt(ga) + " " + toDecInt(gb) + " " + toDecInt(gab)
	io.WriteString(h, val)

	k := hex.EncodeToString(h.Sum(nil))

	return k
}

func main() {

	if len(os.Args) != 3 {
		fmt.Printf(usage)
		os.Exit(1)
	}

	cipherFile := os.Args[1]
	secretFile := os.Args[2]

	cipherText, gb := readCiphertextFromFile(cipherFile)
	p, g, a := readSecretKeyFromFile(secretFile)
	k := generateKey(p, g, gb, a)

	plaintext := decryptCiphertext(cipherText, k)
	fmt.Printf("%s", plaintext)
}
