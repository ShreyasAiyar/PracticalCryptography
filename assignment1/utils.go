package main

import (
	"io/ioutil"
	"log"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// CalculateIOC calculates the Index of Coincidence for a given text.
func CalculateIOC(text string) float64 {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ioc := float64(0)
	length := float64(len(text))
	for i := 0; i < 26; i++ {
		temp := float64(strings.Count(text, string(alphabet[i])))
		ioc += (temp * (temp - 1))
	}
	return ioc / float64(length*(length-1))
}

// CalculateTrigramFrequency calculates the trigram Frequency for a given text.
func CalculateTrigramFrequency(text string, m map[string]float64) float64 {
	length := len(text)
	score := float64(0)
	for i := 0; i < length-2; i++ {
		trigram := string(text[i : i+3])

		if val, ok := m[trigram]; ok {
			score += val
		}
	}
	return score
}

// SplitLink splits a string with a separator and returns two elements
func SplitLink(s, sep string) (string, string) {
	x := strings.Split(s, sep)
	return x[0], x[1]
}

// CreateTrigramDictionary creates a Dictionary of Trigram as the Key and the Frequency as the Value
func CreateTrigramDictionary() map[string]float64 {

	m := make(map[string]float64)
	filename := string("english_trigrams.txt")

	// Keeps track of the total Frequency
	total := float64(0)

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	bytes, err := ioutil.ReadAll(file)

	result := strings.Split(string(bytes), "\n")

	for i := range result {

		trigram, frequency := SplitLink(result[i], " ")
		freq, err := strconv.Atoi(frequency)

		if err != nil {
			log.Fatal(err)
		}

		m[trigram] = float64(freq)
		total += float64(freq)
	}

	// Now we divide each element by the Total Frequency.
	for k, v := range m {
		m[k] = math.Log(v / total)
	}
	return m
}

// CharToIndex returns the alphabet index of a given letter.
func CharToIndex(char byte) int {
	return int(char - 'A')
}

// IndexToChar returns the letter with a given alphabet index.
func IndexToChar(index int) byte {
	return byte('A' + index)
}

// SanitizePlaintext will prepare a string to be encoded
// in the Enigma machine: everything except A-Z will be
// stripped, spaces will be replaced with "X".
func SanitizePlaintext(plaintext string) string {
	plaintext = strings.TrimSpace(plaintext)
	plaintext = strings.ToUpper(plaintext)
	plaintext = strings.Replace(plaintext, " ", "", -1)
	plaintext = regexp.MustCompile(`[^A-Z]`).ReplaceAllString(plaintext, "X")
	return plaintext
}
