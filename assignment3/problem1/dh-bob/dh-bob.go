package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

var usage = `
dh-bob <filename of message from Alice> <filename of message back to Alice>.

Reads in Alice’s message, outputs ( g^b ) to Alice, prints the shared secret g^ab.

Note:
p = 1024 bits and q = 160 bits by default. To change this, edit the const's L and m
`

// L is the bit size for p
const L = 20

// Bit size for q
const m = 10

// Generates the DH Parameter b and computes g^b (mod p). Returns g^b (mod p) and g^(ab) (mod p)
func generateDHParams(p, g, ga *big.Int) (*big.Int, *big.Int) {

	// Generate random PrivateKeySize number of bits for b
	b, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(L), nil))

	if err != nil {
		fmt.Printf("Error creating random Big Int %x\n", err)
		os.Exit(1)
	}

	// Compute g^(b) (mod p)
	gb := new(big.Int).Exp(g, b, p)

	// Compute g^(ab) (mod p)
	gab := new(big.Int).Exp(ga, b, p)

	return gb, gab
}

// Returns DH Params stored as ( p, g, ga )
func readDHParametersFromFile(name string) (*big.Int, *big.Int, *big.Int) {

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

func checkError(err error) {
	if err != nil {
		fmt.Printf("%x", err)
		os.Exit(1)
	}
}

func main() {

	if len(os.Args) != 3 {
		fmt.Printf(usage)
		os.Exit(1)
	}

	p, g, ga := readDHParametersFromFile(os.Args[1])
	gb, gab := generateDHParams(p, g, ga)

	fmt.Printf("g^(ab) (mod p) is %d", gab)

	msgF, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE, 0644)
	checkError(err)

	_, err = msgF.WriteString(fmt.Sprintf("( %d )", gb))
	checkError(err)

}
