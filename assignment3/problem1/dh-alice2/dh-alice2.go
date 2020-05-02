package main

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

var usage = `
dh-alice2 <filename of message from Bob> <filename to read secret key>.

Reads in Bob’s message and Alice’s stored secret, prints the shared secret g^(ab) (mod p)
`

func checkError(err error) {
	if err != nil {
		fmt.Printf("%x", err)
		os.Exit(1)
	}
}

// Returns p, a
func readSecretKeyFromFile(name string) (*big.Int, *big.Int) {

	str, err := ioutil.ReadFile(name)
	if err != nil {
		fmt.Printf("%x\n", err)
	}
	s := string(str)

	// Strip out the "( " and the " )"
	s = strings.TrimLeft(s, "( ")
	s = strings.TrimRight(s, " )")

	params := strings.Split(s, ",")

	if len(params) != 3 {
		fmt.Printf("There should be atleast 3 parameters ( p, g, a ) in the file %x\n", name)
		os.Exit(1)
	}

	p, _ := new(big.Int).SetString(params[0], 10)
	a, _ := new(big.Int).SetString(params[2], 10)

	return p, a

}

// Returns gb
func readBobMsgFromFile(name string) *big.Int {

	str, err := ioutil.ReadFile(name)
	if err != nil {
		fmt.Printf("%x\n", err)
	}
	s := string(str)

	// Strip out the "( " and the " )"
	s = strings.TrimLeft(s, "( ")
	s = strings.TrimRight(s, " )")

	gb, _ := new(big.Int).SetString(s, 10)

	return gb
}

// Generates shared secret g^(ab) (mod p)
func generateSharedSecret(p, a, gb *big.Int) *big.Int {

	return new(big.Int).Exp(gb, a, p)
}

func main() {

	if len(os.Args) != 3 {
		fmt.Printf("%s", usage)
		return
	}

	p, a := readSecretKeyFromFile(os.Args[2])
	gb := readBobMsgFromFile(os.Args[1])

	gab := generateSharedSecret(p, a, gb)
	fmt.Printf("g^(ab) (mod p) is %d", gab)
}
