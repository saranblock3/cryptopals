package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/saranblock3/cryptopals/pkg/oracles/aesecb"
	"github.com/saranblock3/cryptopals/pkg/utils"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"time"
)

// 1
func q1() {
	cipherTextHex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	cipherTextBytes, err := hex.DecodeString(cipherTextHex)
	handleError(err)
	res := base64.StdEncoding.EncodeToString(cipherTextBytes)

	fmt.Println("Hex String:         ", cipherTextHex)
	fmt.Println("Base 64 String:     ", res)
}

// 2
func q2() {
	cipherTextHex0 := "1c0111001f010100061a024b53535009181c"
	cipherTextHex1 := "686974207468652062756c6c277320657965"
	cipherTextBytes0, err := hex.DecodeString(cipherTextHex0)
	handleError(err)
	cipherTextBytes1, err := hex.DecodeString(cipherTextHex1)
	handleError(err)
	xorBytes, err := utils.XorByteSlice(cipherTextBytes0, cipherTextBytes1)
	handleError(err)
	xorHex := hex.EncodeToString(xorBytes)

	fmt.Println("Hex string 1:       ", cipherTextHex0)
	fmt.Println("Hex string 2:       ", cipherTextHex1)
	fmt.Println("XORed string:       ", xorHex)
}

// 3
func q3() {
	cipherTextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherTextBytes, err := hex.DecodeString(cipherTextHex)
	handleError(err)
	key, plainText, _ := utils.DecryptSingleByteXor(cipherTextBytes)

	fmt.Println("Cipher text hex:    ", cipherTextHex)
	fmt.Println("Key:                ", string(key))
	fmt.Println("Plain text:         ", plainText)
}

// 4
func q4() {
	cipherTextHexSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/4.txt")
	var chosenCipherText string
	var key byte
	var plainText string
	var lowestMse float64 = math.Inf(1)
	for _, currentCipherTextBytes := range cipherTextHexSlices {
		cipherTextBytes, err := hex.DecodeString(string(currentCipherTextBytes))
		handleError(err)
		currentKey, testPlainText, currentMse := utils.DecryptSingleByteXor(cipherTextBytes)
		if currentMse < lowestMse {
			chosenCipherText = string(currentCipherTextBytes)
			key = currentKey
			plainText = testPlainText
			lowestMse = currentMse
		}
	}

	fmt.Println("Cipher text hex:    ", chosenCipherText)
	fmt.Println("Key:                ", string(key))
	fmt.Println("Plain text:         ", plainText)
}

// 5
func q5() {
	plainTextBytes := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	cipherTextBytes := utils.RepeatingXor(plainTextBytes, key)
	cipherTextHex := hex.EncodeToString(cipherTextBytes)

	fmt.Println("Plain text:         ", string(plainTextBytes))
	fmt.Println("Key:                ", string(key))
	fmt.Println("Cipher text hex:    ", cipherTextHex)
}

// 6
func q6() {
	cipherTextHexSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/6.txt")
	cipherTextHex := bytes.Join(cipherTextHexSlices, []byte(""))
	cipherTextBytes, err := base64.StdEncoding.DecodeString(string(cipherTextHex))
	handleError(err)

	keySize := utils.FindKeySize(cipherTextBytes)

	key := utils.FindRepeatingXorKey(cipherTextBytes, keySize)
	plainText := utils.RepeatingXor(cipherTextBytes, key)

	fmt.Println("Key:                ", string(key))
	fmt.Println("Plain text:         ", string(plainText))
}

// 7
func q7() {
	cipherTextHexSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/7.txt")
	cipherTextHex := bytes.Join(cipherTextHexSlices, []byte(""))
	cipherTextBytes, err := base64.StdEncoding.DecodeString(string(cipherTextHex))
	handleError(err)
	key := []byte("YELLOW SUBMARINE")
	plainText := aesecb.Decrypt(cipherTextBytes, key)

	fmt.Println("Key:                ", string(key))
	fmt.Println("Plain text:         ", string(plainText))
}

// 8
func q8() {
	cipherTextHexSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/8.txt")
	var cipherTextByteSlices [][]byte
	for _, currentSlice := range cipherTextHexSlices {
		currentByteSlice, err := hex.DecodeString(string(currentSlice))
		handleError(err)
		cipherTextByteSlices = append(cipherTextByteSlices, currentByteSlice)
	}
	var chosenBytes []byte
	for _, currentSlice := range cipherTextByteSlices {
		if utils.IsEcbEncrypted(currentSlice) {
			chosenBytes = currentSlice
		}
	}

	fmt.Println("ECB encrypted text:", hex.EncodeToString(chosenBytes))
}

func main() {
	runAndFormatSolutions()

}

// helper functions

var solutions []func() = []func(){q1, q2, q3, q4, q5, q6, q7, q8}

func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}

func runAndFormatSolutions() {
	for i := 0; i < len(solutions); i++ {
		formatPuzzleOutputTop(i + 1)
		startTime := time.Now()
		solutions[i]()
		elapsedTime := time.Since(startTime)
		formatPuzzleOutputBottom()
		log.Printf("Execution time: %s", elapsedTime)
		paddingBottom()
	}
}

func formatPuzzleOutputTop(puzzleNumber int) {
	fmt.Println("Puzzle", puzzleNumber)
	fmt.Println("========================================")
}

func formatPuzzleOutputBottom() {
	fmt.Println("========================================")
}

func paddingBottom() {
	fmt.Println()
	fmt.Println()
	fmt.Println()
}

func getByteSlicesFromUrl(url string) [][]byte {
	resp, err := http.Get(url)
	handleError(err)
	defer resp.Body.Close()
	text, err := ioutil.ReadAll(resp.Body)
	handleError(err)
	strings := bytes.Split(text, []byte("\n"))
	return strings
}
