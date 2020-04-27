package main

import "bytes"

// Enigma represents an Enigma machine with configured rotors, plugs,
// and a reflector. Most states are stored in the rotors themselves.
type Enigma struct {
	Reflector Reflector
	Plugboard Plugboard
	Rotors    []*Rotor
}

// RotorConfig reprensents a configuration for a rotor as set by the user:
// ID from the pre-defined list, a starting position (A to Z), and a ring
// setting (1 to 26).
type RotorConfig struct {
	ID    string
	Start byte
	Ring  int
}

// NewEnigma is the Enigma constructor, accepting an array of RotorConfig objects
// for rotors, a reflector ID/name, and an array of plugboard pairs.
func NewEnigma(rotorConfiguration []RotorConfig, refID string, plugs string) *Enigma {
	rotors := make([]*Rotor, len(rotorConfiguration))
	for i, configuration := range rotorConfiguration {
		rotors[i] = HistoricRotors.GetByID(configuration.ID)
		rotors[i].Offset = CharToIndex(configuration.Start)
		rotors[i].Ring = configuration.Ring - 1
	}
	return &Enigma{*HistoricReflectors.GetByID(refID), *NewPlugboardAlternate(plugs), rotors}
}

func (e *Enigma) moveRotors() {
	var (
		rotorLen            = len(e.Rotors)
		farRight            = e.Rotors[rotorLen-1]
		farRightTurnover    = farRight.ShouldTurnOver()
		secondRight         = e.Rotors[rotorLen-2]
		secondRightTurnover = secondRight.ShouldTurnOver()
		thirdRight          = e.Rotors[rotorLen-3]
	)
	if secondRightTurnover {
		if !farRightTurnover {
			secondRight.move(1)
		}
		thirdRight.move(1)
	}
	if farRightTurnover {
		secondRight.move(1)
	}
	farRight.move(1)
}

// EncodeChar encodes a single character.
func (e *Enigma) EncodeChar(letter byte) byte {
	e.moveRotors()

	letterIndex := CharToIndex(letter)
	letterIndex = e.Plugboard[letterIndex]

	for i := len(e.Rotors) - 1; i >= 0; i-- {
		letterIndex = e.Rotors[i].Step(letterIndex, false)
	}

	letterIndex = e.Reflector.Sequence[letterIndex]

	for i := 0; i < len(e.Rotors); i++ {
		letterIndex = e.Rotors[i].Step(letterIndex, true)
	}

	letterIndex = e.Plugboard[letterIndex]
	letter = IndexToChar(letterIndex)

	return letter
}

// EncodeString encodes a string.
func (e *Enigma) EncodeString(text string) string {
	var result bytes.Buffer
	for i := range text {
		result.WriteByte(e.EncodeChar(text[i]))
	}
	return result.String()
}
