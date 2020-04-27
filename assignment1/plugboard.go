package main

import (
	"strings"
)

// Plugboard is a two-way mapping between characters modifying the
// encoding procedure of the Enigma machine.
type Plugboard [26]int

// NewPlugboard is the plugboard constructor accepting an array
// of two-symbol strings representing plug pairs.
func NewPlugboard(pairs []string) *Plugboard {
	p := Plugboard{}
	for i := 0; i < 26; i++ {
		p[i] = i
	}
	for _, pair := range pairs {
		if len(pair) > 0 {
			var intFirst = CharToIndex(pair[0])
			var intSecond = CharToIndex(pair[1])
			p[intFirst] = intSecond
			p[intSecond] = intFirst
		}
	}
	return &p
}

// NewPlugboardAlternate is an alternate implementation of the NewPlugboard function.
func NewPlugboardAlternate(plugboard string) *Plugboard {
	p := Plugboard{}
	for i := 0; i < 26; i++ {
		p[i] = i
	}
	base := string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	for i := 0; i < 26; i++ {

		character := string(plugboard[i])
		index := strings.Index(base, character)
		p[i] = index
	}
	return &p
}
