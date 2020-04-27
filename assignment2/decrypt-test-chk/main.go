package main

import (
	"flag"
	"fmt"
	"os/exec"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	var filePtr = flag.String("i", "", "input file")
	flag.Parse()

	key := "2b7e151628aed2a6abf7158809cf4f3c"
	inputFile := *filePtr
	outputFile := "output.txt"

	output, error := exec.Command("./encrypt-auth-chk", "decrypt", key, inputFile, outputFile).Output()
	check(error)

	if string(output) == "INVALID CHECKSUM" {
		fmt.Print("INVALID CHECKSUM")
	} else {
		fmt.Print("SUCCESS")
	}

}
