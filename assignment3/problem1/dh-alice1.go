package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
)

var usage = `
dh-alice1 <filename for message to Bob> <filename to store secret key>
`

func toHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n)
}

func printBitLength(n *big.Int) {
	length := n.BitLen()
	fmt.Printf("%d\n", length)
}

// XORBytes takes two byte slices and XOR's them
func XORBytes(b1 []byte, b2 []byte) []byte {

	if len(b1) != len(b2) {
		fmt.Printf("Byte sequence b1 has length %d and b2 has length %d \n", len(b1), len(b2))
		return nil
	}

	b3 := make([]byte, len(b1))

	for i := 0; i < len(b1); i++ {
		b3[i] = b1[i] ^ b2[i]
	}
	return b3
}

// PrivateKeySize is the bit size for a, b
const PrivateKeySize = 256

// Assuming m=160 for now, should probably be fixed later.
func generateQ(L int, m int) (*big.Int, *big.Int) {

	// Select an arbitrary bit string SEED such that the length of SEED >= m
	seed := new(big.Int)

	// z1 is 2^m
	z1 := new(big.Int)
	z1.Exp(big.NewInt(2), big.NewInt(int64(m)), nil)

	seed, err := rand.Int(rand.Reader, z1)
	if err != nil {
		fmt.Printf("Error creating random Big Int %x\n", err)
		os.Exit(1)
	}

	seed.Add(seed, z1)
	seedcp := seed

	// Set U = 0
	U := new(big.Int)

	// U = SHA1[SEED] XOR SHA1[(SEED+1) mod 2^160 ]
	h1 := sha1.New()
	h2 := sha1.New()
	io.WriteString(h1, toHexInt(seedcp))

	seedcp.Add(seedcp, big.NewInt(1))
	seedcp.Mod(seedcp, z1)
	io.WriteString(h2, toHexInt(seedcp))

	val := XORBytes(h1.Sum(nil), h2.Sum(nil))

	U.SetString(hex.EncodeToString(val), 16)

	// Form q from U by computing U mod (2^m) and setting the most significant bit (the 2^(m-1) bit) and the least significant bit to 1.
	// In terms of boolean operations, q = U OR 2^(m-1) OR 1.

	q := new(big.Int)
	U.Mod(U, z1)

	// z2 is 2^(m-1)
	z2 := new(big.Int)
	z2.Exp(big.NewInt(2), big.NewInt(int64(m-1)), nil)

	q.Or(U, big.NewInt(1))
	q.Or(q, z2)

	//  Note that 2^(m-1) < q < 2^m => z2 < q < z1
	if q.Cmp(z1) != -1 && q.Cmp(z2) != 1 {
		fmt.Printf("q not in desired range \n")
		os.Exit(1)
	}

	return q, seed
}

// Based on https://tools.ietf.org/html/rfc2631#ref-FIPS-186 - Generation of p, q, and g
func generateDHParams(L int, m int) (*big.Int, *big.Int) {

	// Set m' = m/160
	m1 := int64(math.Ceil(float64(m) / 160))

	// // Set L'=  L/160
	L1 := int64(math.Ceil(float64(L) / 160))

	// // Set N'= L/1024
	N1 := int64(math.Ceil(float64(L) / 1024))

	// Define p, q, ssed
	var p *big.Int
	var q *big.Int
	var seed *big.Int

	// https://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa
	for {
		q, seed = generateQ(L, m)
		if q.ProbablyPrime(100) == true {
			break
		}
	}

	// If counter < (4096 * N)
	var counter int64
	for counter = 0; counter < (4096 * N1); counter++ {
		// Set R = seed + 2*m' + (L' * counter)
		R := new(big.Int)
		R.Add(R, seed)
		R.Add(R, big.NewInt(2*int64(m1)))
		R.Add(R, new(big.Int).Mul(big.NewInt(L1), big.NewInt(counter)))

		// Set V = 0
		V := big.NewInt(0)

		//  For i = 0 to L'-1 do
		var i int64
		for i = 0; i <= L1-1; i++ {

			//  V = V + SHA1(R + i) * 2^(160 * i)
			h := sha1.New()
			io.WriteString(h, toHexInt(new(big.Int).Add(R, big.NewInt(i))))
			val := h.Sum(nil)
			temp1, bool := new(big.Int).SetString(hex.EncodeToString(val), 16)

			if bool != true {
				fmt.Printf("Error setting String \n")
			}

			temp2 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Mul(big.NewInt(160), big.NewInt(i)), nil)

			V.Add(V, new(big.Int).Mul(temp1, temp2))
		}

		// Set W = V mod 2^L
		W := new(big.Int).Mod(V, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(L)), nil))

		// Set X = W OR 2^(L-1)
		X := new(big.Int).Or(W, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(L-1)), nil))

		// Set p = X - (X mod (2*q)) + 1
		p = big.NewInt(0)
		temp1 := new(big.Int).Mod(X, new(big.Int).Mul(big.NewInt(2), q))
		p.Sub(X, temp1)
		p.Add(p, big.NewInt(1))

		// If p > 2^(L-1) use a robust primality test to test whether p is prime

		if p.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(L)-1), nil)) == 1 {
			if p.ProbablyPrime(5000) == true {
				return p, q
			}
		}
	}
	return nil, nil
}

func main() {

	args := os.Args[1:]

	if len(args) != 2 {
		fmt.Printf("%s", usage)
		return
	}
	p, q := generateDHParams(20, 8)
	fmt.Printf("p is %d \nq is %d \n", p, q)

	// msgFile := args[0]
	// secretFile := args[1]

}
