package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
)

var filePtr *string

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func callOracle(C []byte) bool {

	ioutil.WriteFile("test.txt", C, 0666)

	output, _ := exec.Command("./decrypt-test", "-i=test.txt").Output()

	if string(output) == "INVALID PADDING" {
		return false
	}
	return true
}

func decryptCipherBlock(C []byte, CPrev []byte) []byte {

	// Intermediate block
	inter := make([]byte, 16)

	// Guess for the previous block
	guess := make([]byte, 16)

	// Current byte
	curr := byte(1)

	// Loop from the last byte to the first byte
	for i := 15; i >= 0; i-- {
		for j := 0; j <= 255; j++ {
			guess[i] = byte(j)

			// Call the Oracle
			success := callOracle(append(guess, C...))
			if success {
				inter[i] = curr ^ byte(j)
				curr++
				for k := 15; k >= i; k-- {
					guess[k] = curr ^ inter[k]
				}
				break
			}
		}
	}

	for i := 0; i < 16; i++ {
		inter[i] = inter[i] ^ CPrev[i]
	}
	return inter
}

func decryptCiphertext(C []byte) []byte {

	// prev is IV initially
	prev := C[0:16]

	plaintext := make([]byte, 0)
	for i := 16; i < len(C); i += 16 {

		temp := decryptCipherBlock(C[i:i+16], prev)
		prev = C[i : i+16]
		plaintext = append(plaintext, temp...)
	}
	lastByte := int(plaintext[len(plaintext)-1])
	return plaintext[0 : len(plaintext)-lastByte-32]
}

func main() {

	filePtr = flag.String("i", "", "input file")
	flag.Parse()

	text, err := ioutil.ReadFile(*filePtr)
	check(err)

	fmt.Println(string(decryptCiphertext(text)))

}
