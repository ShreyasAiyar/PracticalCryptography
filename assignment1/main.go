package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

// CLIDefaults is the defaults for the Engima Rotor.
var CLIDefaults = struct {
	Reflector string
	Ring      string
	Position  string
	Rotors    string
	Plugboard string
}{
	Reflector: "C-thin",
	Ring:      "1 1 1 16",
	Position:  "A A B Q",
	Rotors:    "I II IV III",
	Plugboard: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}

// SetDefaultsForEnigmaMachine sets the defaults for the Engima Machine and returns an Engima Machine.
func SetDefaultsForEnigmaMachine() *Enigma {

	rotorArray := strings.Split(CLIDefaults.Rotors, " ")
	var ringArray []int = make([]int, len(strings.Split(CLIDefaults.Ring, " ")))

	posArray := strings.Split(CLIDefaults.Position, " ")
	for idx, val := range strings.Split(CLIDefaults.Ring, " ") {
		ringArray[idx], _ = strconv.Atoi(val)
	}

	config := make([]RotorConfig, len(rotorArray))
	for index, rotor := range rotorArray {
		ring := ringArray[index]
		value := posArray[index][0]
		config[index] = RotorConfig{ID: rotor, Start: value, Ring: ring}
	}

	//plugboards := strings.Split(CLIDefaults.Plugboard, " ")
	plugboards := string(CLIDefaults.Plugboard)
	e := NewEnigma(config, CLIDefaults.Reflector, plugboards)

	return e
}

// ReadFileContents returns the contents of a file
func ReadFileContents() string {
	args := os.Args[1]
	file, err := os.Open(args)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)

	return string(bytes)
}

// SwapCharacters swaps char1 and char2 in Plugboard
func SwapCharacters(char1 string, char2 string, plugboard string) string {

	plugboard = strings.Replace(plugboard, char1, ",", 1)
	plugboard = strings.Replace(plugboard, char2, char1, 1)
	plugboard = strings.Replace(plugboard, ",", char2, 1)

	return plugboard
}

// SwapCharactersFast is a faster implementation of SwapCharacters
func SwapCharactersFast(char1 string, char2 string, plugboard string) string {

	index1 := strings.Index(plugboard, char1)
	index2 := strings.Index(plugboard, char2)
	plugboard = plugboard[0:index1] + char2 + plugboard[index1+1:]
	plugboard = plugboard[0:index2] + char1 + plugboard[index2+1:]

	return plugboard
}

// SetEnigmaAndGetScore changes the plugboard and returns the IOC of the decoded plaintext
func SetEnigmaAndGetScore(plugboard string, ciphertext string, function string, m map[string]float64) float64 {

	CLIDefaults.Plugboard = plugboard
	enigma := SetDefaultsForEnigmaMachine()
	decoded := enigma.EncodeString(ciphertext)
	score := float64(0)
	if function == "ioc" {
		score = CalculateIOC(decoded)
	} else {
		score = CalculateTrigramFrequency(decoded, m)
	}
	return score
}

// IteratePlugboard iterates through the plugboard once
func IteratePlugboard(max float64, plugboard string, ciphertext string, function string, m map[string]float64) string {
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	hash := make(map[string]bool)

	// Two Loops. Outer Loop iterates through the entire range of letters
	for i := 0; i < 26; i++ {

		actual1 := string(base[i])
		current1 := string(plugboard[i])

		// temp stores the best possible plugboard for that loop
		temp := plugboard
		def := plugboard

		// Inner Loop iterates through from that character to the end
		for j := i + 1; j < 26; j++ {

			plugboard = def

			actual2 := string(base[j])
			current2 := string(plugboard[j])

			// We swap everything back to it's initial positions
			plugboard = SwapCharactersFast(actual1, current1, plugboard)
			plugboard = SwapCharactersFast(actual2, current2, plugboard)

			// Now we can try 4 different plugboard alternatives
			// We have to find the best alternative from these

			values := []string{}
			temp1 := SwapCharactersFast(actual1, current1, plugboard)
			temp2 := SwapCharactersFast(actual1, current2, plugboard)
			temp3 := SwapCharactersFast(actual2, current1, plugboard)
			temp4 := SwapCharactersFast(actual2, current2, plugboard)

			if hash[temp1] != true {
				hash[temp1] = true
				values = append(values, temp1)
			}
			if hash[temp2] != true {
				hash[temp2] = true
				values = append(values, temp2)
			}
			if hash[temp3] != true {
				hash[temp3] = true
				values = append(values, temp3)
			}
			if hash[temp4] != true {
				hash[temp4] = true
				values = append(values, temp4)
			}

			for _, value := range values {
				score := SetEnigmaAndGetScore(value, ciphertext, function, m)
				if score > max {
					temp = value
					max = score
				}
			}
		}
		plugboard = temp
	}
	return plugboard
}

// HillClimbAttack performs the HillClimb Attack
func HillClimbAttack(ciphertext string, m map[string]float64) (string, float64, float64) {

	// Initial Attack Based on IOC Score
	base := string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	score := SetEnigmaAndGetScore(base, ciphertext, "ioc", m)
	plugboard := IteratePlugboard(score, base, ciphertext, "ioc", m)

	//Second Attack Based on Trigram Score
	score = SetEnigmaAndGetScore(plugboard, ciphertext, "trigram", m)
	plugboard = IteratePlugboard(score, plugboard, ciphertext, "trigram", m)

	trigram := SetEnigmaAndGetScore(plugboard, ciphertext, "trigram", m)
	ioc := SetEnigmaAndGetScore(plugboard, ciphertext, "ioc", m)

	return plugboard, trigram, ioc
}

// IterateHillClimbAttack iterates through the HillClimbAttack
func IterateHillClimbAttack(ciphertext string, dict map[string]float64) (string, string, string) {
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	baseRotor := string("?1 ?2 IV III")
	basePosition := string("?1 ?2 B Q")
	rotors := []string{"I", "II", "V", "VI", "Beta", "Gamma"}
	positions := string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	// Keep Track of the best Plugboard and Score
	bestScore := math.Inf(-100)
	bestPlugboard := string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	bestRotor := ""
	bestPosition := ""

	total := float64(0)
	count := float64(0)
	// Loop through the Rotors
	for i := 0; i < len(rotors); i++ {

		for j := 0; j < len(rotors); j++ {

			if i == j {
				continue
			}

			rotor := strings.Replace(baseRotor, "?1", string(rotors[i]), 1)
			rotor = strings.Replace(rotor, "?2", string(rotors[j]), 1)

			CLIDefaults.Rotors = rotor

			// Now loop through the Positions

			for m := 0; m < len(positions); m++ {

				for n := 0; n < len(positions); n++ {

					position := strings.Replace(basePosition, "?1", string(positions[m]), 1)
					position = strings.Replace(position, "?2", string(positions[n]), 1)

					CLIDefaults.Position = position

					// Optimization - Let's not consider this if it's IOC is less than the average so far:
					ioc := SetEnigmaAndGetScore(base, ciphertext, "ioc", dict)

					if total == 0 {
						total = ioc
						count++
					} else if ioc <= total/count {
						continue
					} else if ioc > total/count {
						total += ioc
						count++
					}

					plugboard, trigram, _ := HillClimbAttack(ciphertext, dict)
					if trigram > bestScore {
						bestScore = trigram
						bestPlugboard = plugboard
						bestRotor = rotor
						bestPosition = position
					}

				}
			}
		}
	}
	return bestPlugboard, bestRotor, bestPosition

}

// FormatPlugboard formats the Plugboard string into a list of plugboard pairs
func FormatPlugboard(plugboard string) string {

	formatted := string("")
	base := string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	for i := 0; i < len(plugboard); i++ {

		actual := string(base[i])
		current := string(plugboard[i])

		if actual != current && !strings.Contains(formatted, actual) && !strings.Contains(formatted, current) {
			formatted = formatted + actual + current + " "
		}

	}

	return formatted
}

func main() {
	// Read File Contents
	ciphertext := ReadFileContents()
	m := CreateTrigramDictionary()

	bestPlugboard, bestRotor, bestPosition := IterateHillClimbAttack(ciphertext, m)
	CLIDefaults.Rotors = bestRotor
	CLIDefaults.Position = bestPosition
	CLIDefaults.Plugboard = bestPlugboard

	fmt.Println(bestRotor)
	fmt.Println(bestPosition)
	fmt.Println(FormatPlugboard(bestPlugboard))

}
