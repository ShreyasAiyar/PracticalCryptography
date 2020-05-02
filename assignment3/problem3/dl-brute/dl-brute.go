package main

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

var usage = `
dl-brute <filename for inputs>.
On input a file containing decimal-formatted ( p, g, h ), prints x to standard output.`

// Finds an integer x such that g^x ≡ h mod p. Returns x
func bruteforceSecretKey(p, g, h *big.Int) *big.Int {

	x := big.NewInt(1)
	fmt.Printf("%d, %d, %d\n", p, g, h)

	for {
		temp := new(big.Int).Exp(g, x, p)
		if temp.Cmp(h) == 0 {
			fmt.Printf("%d\n", temp)
			break
		}
		x.Add(x, big.NewInt(1))
	}
	return x
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

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("%s\n", usage)
		os.Exit(1)
	}

	p, g, ga := readPublicKeyFromFile(os.Args[1])
	x := bruteforceSecretKey(p, g, ga)

	fmt.Printf("%d\n", x)
}
