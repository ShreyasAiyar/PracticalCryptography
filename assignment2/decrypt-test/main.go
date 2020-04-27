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

	key := "2b7e151628aed2a6abf7158809cf4f3cf4673bc171a61ed4e877a3976b044458"
	inputFile := *filePtr
	outputFile := "output.txt"

	output, error := exec.Command("./encrypt-auth", "decrypt", key, inputFile, outputFile).Output()
	check(error)

	if string(output) == "INVALID PADDING" {
		fmt.Print("INVALID PADDING")
	} else if string(output) == "INVALID MAC" {
		fmt.Print("INVALID MAC")
	} else {
		fmt.Print("SUCCESS")
	}

}
