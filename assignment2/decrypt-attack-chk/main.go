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

func callOracle(IV []byte, C []byte) bool {

	result := append(IV, C...)
	ioutil.WriteFile("test.txt", result, 0666)

	output, _ := exec.Command("./decrypt-test-chk", "-i=test.txt").Output()

	if string(output) == "INVALID CHECKSUM" {
		return false
	}
	return true
}

func decryptCiphertext(block []byte, IV []byte) []byte {

	// length is the length of the plaintext
	length := len(block)

	// Create plaintext
	M := make([]byte, 0)

	// initial value of inter is only the checksum
	inter := make([]byte, 1)
	for j := 0; j < 255; j++ {
		inter[0] = byte(j)
		success := callOracle(IV, inter)
		if success {
			break
		}
	}
	// We iterate through the length of the plaintext
	for i := 1; i < length; i++ {

		// temp is a guess for the next byte
		temp := make([]byte, 1)
		for j := 0; j <= 255; j++ {
			temp[0] = byte(j)
			success := callOracle(IV, append(inter, temp...))
			if success {
				plaintext := block[i] ^ byte(j)
				M = append(M, plaintext)
				inter = append(inter, temp...)
				break
			}
		}
	}
	return M
}

func main() {

	filePtr = flag.String("i", "", "input file")
	flag.Parse()

	C, err := ioutil.ReadFile(*filePtr)
	check(err)

	IV := make([]byte, 16)
	copy(IV, C[0:16])
	C = C[16:]

	fmt.Println(string(decryptCiphertext(C, IV)))

}
