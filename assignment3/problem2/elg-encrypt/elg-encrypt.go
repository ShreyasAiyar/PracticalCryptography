package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
elg-encrypt <message text as a string with quotes> <filename of public key> <filename of ciphertext>.

Reads in the public key ( p, g, ga ) produced by elg-keygen. Generates b and computes k = SHA256(ga∥gb∥gab). 
Outputs ( gb,AESGCMk(M) ) to a ciphertext file, where the latter value is encoded as a hexadecimal string.

Note:
p = 1024 bits and q = 160 bits by default. To change this, edit the const's L and m
`

// L is the bit size for p
const L = 20

// Bit size for q
const m = 10

func toDecInt(n *big.Int) string {
	return fmt.Sprintf("%d", n)
}

// Returns public key (p, g, ga)
func readPublicKeyFromFile(name string) (*big.Int, *big.Int, *big.Int) {
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
		fmt.Printf("There should be atleast 3 parameters ( p, g, ga ) in the file %x\n", name)
		os.Exit(1)
	}

	// Hoping they unmarshal correctly - base is 10 since decimal
	p, _ := new(big.Int).SetString(params[0], 10)
	g, _ := new(big.Int).SetString(params[1], 10)
	ga, _ := new(big.Int).SetString(params[2], 10)

	return p, g, ga
}

// Returns Key k
func generateKey(p, g, ga *big.Int) (string, *big.Int) {

	// Generate b
	b, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(L), nil))
	checkError(err)

	// Compute k = SHA256(ga | gb | gab)
	gb := new(big.Int).Exp(g, b, p)
	gab := new(big.Int).Exp(ga, b, p)

	h := sha256.New()

	// For compatibility, please encode your input to SHA256 using decimal formatted integers separated by a single space character.
	val := toDecInt(ga) + " " + toDecInt(gb) + " " + toDecInt(gab)
	io.WriteString(h, val)

	k := hex.EncodeToString(h.Sum(nil))

	return k, gb
}

// Returns enciphered message with AES GCM under Key k
func encipherMessage(M string, k string) string {

	key, err := hex.DecodeString(k)
	checkError(err)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// Copy nonce to IV
	IV := make([]byte, 12)
	copy(IV, nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(M), nil)

	// Append the IV to the Ciphertext
	ciphertext = append(nonce, ciphertext...)

	return string(ciphertext)
}

func checkError(err error) {
	if err != nil {
		fmt.Printf("%x", err)
		os.Exit(1)
	}
}

func main() {

	if len(os.Args) != 4 {
		fmt.Printf("%x", usage)
	}

	msgFile := os.Args[1]
	pkFile := os.Args[2]
	cipherFile := os.Args[3]

	p, g, ga := readPublicKeyFromFile(pkFile)
	k, gb := generateKey(p, g, ga)

	str, err := ioutil.ReadFile(msgFile)
	checkError(err)

	ciphertext := encipherMessage(string(str), k)

	outputFile, err := os.OpenFile(cipherFile, os.O_WRONLY|os.O_CREATE, 0644)
	checkError(err)

	_, err = outputFile.WriteString(fmt.Sprintf("( %d,%x )", gb, ciphertext))
	checkError(err)

	defer outputFile.Close()

}
