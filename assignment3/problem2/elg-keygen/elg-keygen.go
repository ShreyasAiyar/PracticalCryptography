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
elg-keygen elg-keygen <filename to store public key> <filename to store secret key>.

Writes decimal-formatted public key ( p, g, ga ) to the first file and writes (p, g, a) to a second file.

Note:
p = 1024 bits and q = 160 bits by default. To change this, edit the const's L and m
`

// L is the bit size for p
const L = 1024

// Bit size for q
const m = 160

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

// Does not work for m >= 160 yet
func generateQ(m int64) (*big.Int, *big.Int) {

	// Select an arbitrary bit string SEED such that the length of SEED >= m
	seed := new(big.Int)

	// z1 is 2^m
	z1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(m), nil)

	// z2 is 2^(m-1)
	z2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(m-1), nil)

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

	q.Or(U, big.NewInt(1))
	q.Or(q, z2)

	//  Note that 2^(m-1) < q < 2^m => z2 < q < z1
	if q.Cmp(z1) != -1 && q.Cmp(z2) != 1 {
		fmt.Printf("q not in desired range \n")
		os.Exit(1)
	}

	return q, seed
}

// Based on https://tools.ietf.org/html/rfc2631#ref-FIPS-186 - Generation of p and q
func generatePQ(L int64, m int64) (*big.Int, *big.Int) {

	// Set m' = m/160
	m1 := int64(math.Ceil(float64(m) / 160))

	// Set L'=  L/160
	L1 := int64(math.Ceil(float64(L) / 160))

	// Set N'= L/1024
	N1 := int64(math.Ceil(float64(L) / 1024))

	// Define p, q, seed
	var p *big.Int
	var q *big.Int
	var seed *big.Int

	// https://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa
	for {
		q, seed = generateQ(m)
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
		R.Add(R, big.NewInt(2*m1))
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
				os.Exit(1)
			}

			temp2 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Mul(big.NewInt(160), big.NewInt(i)), nil)

			V.Add(V, new(big.Int).Mul(temp1, temp2))
		}

		// Set W = V mod 2^L
		W := new(big.Int).Mod(V, new(big.Int).Exp(big.NewInt(2), big.NewInt(L), nil))

		// Set X = W OR 2^(L-1)
		X := new(big.Int).Or(W, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(L-1)), nil))

		// Set p = X - (X mod (2*q)) + 1
		p = big.NewInt(0)
		temp1 := new(big.Int).Mod(X, new(big.Int).Mul(big.NewInt(2), q))
		p.Sub(X, temp1)
		p.Add(p, big.NewInt(1))

		// If p > 2^(L-1) use a robust primality test to test whether p is prime

		if p.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(L-1), nil)) == 1 {
			if p.ProbablyPrime(5000) == true {
				return p, q
			}
		}
	}
	return nil, nil
}

// Returns p, g, ga, a
func generateDHParams(L int64, m int64) (*big.Int, *big.Int, *big.Int, *big.Int) {

	p, q := generatePQ(L, m)

	// Let j = (p - 1)/q.
	j := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), q)

	// Declare g
	var g *big.Int

	for {

		// Set h = any integer, where 1 < h < p - 1 and h differs from any value previously tried.
		h, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))

		if err != nil {
			fmt.Printf("Error creating random Big Int %x\n", err)
			os.Exit(1)
		}
		h.Add(h, big.NewInt(2))

		g = new(big.Int).Exp(h, j, p)

		if g.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}

	// TODO: Verify that p=qj + 1. This demonstrates that the parameters meet the X9.42 parameter criteria.

	// Generate random number a in the range [0, p)
	a, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(L), nil))

	if err != nil {
		fmt.Printf("Error creating random Big Int %x\n", err)
		os.Exit(1)
	}

	// Compute g^a mod p
	ga := new(big.Int).Exp(g, a, p)

	return p, g, ga, a
}

func checkError(err error) {
	if err != nil {
		fmt.Printf("%x", err)
		os.Exit(1)
	}
}

func main() {

	if len(os.Args) != 3 {
		fmt.Printf("%s\n", usage)
		return
	}

	p, g, ga, a := generateDHParams(L, m)

	msgF, err := os.OpenFile(os.Args[1], os.O_WRONLY|os.O_CREATE, 0644)
	checkError(err)

	secretF, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE, 0644)
	checkError(err)

	_, err = msgF.WriteString(fmt.Sprintf("( %d,%d,%d )", p, g, ga))
	checkError(err)

	_, err = secretF.WriteString(fmt.Sprintf("( %d,%d,%d )", p, g, a))
	checkError(err)

	defer msgF.Close()
	defer secretF.Close()
}
