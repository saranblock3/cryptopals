package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/saranblock3/cryptopals/pkg/utils"
	"github.com/saranblock3/cryptopals/resources"
	"golang.org/x/exp/slices"
	"gonum.org/v1/gonum/stat/combin"
	"io/ioutil"
	"math"
	"net/http"
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
	xorByteSlice, err := utils.XorByteSlice(cipherTextBytes0, cipherTextBytes1)
	handleError(err)
	res := hex.EncodeToString(xorByteSlice)

	fmt.Println("Hex string 1:       ", cipherTextHex0)
	fmt.Println("Hex string 2:       ", cipherTextHex1)
	fmt.Println("XORed string:       ", res)
}

// 3
func q3() {
	cipherTextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherTextBytes, err := hex.DecodeString(cipherTextHex)
	handleError(err)
	key, plainText, _ := utils.DecryptSingleByteXor(cipherTextBytes)

	fmt.Println("Cipher text hex:    ", cipherTextHex)
	fmt.Println("Key:                ", key)
	fmt.Println("Plain text:         ", plainText)
}

// 4
func q4() {
	cipherTextHexArray := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/4.txt")
	var chosenCipherText string
	var key byte
	var plainText string
	var lowestMse float64 = math.Inf(1)
	for _, currentCipherTextBytes := range cipherTextHexArray {
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
	fmt.Println("Key:                ", key)
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

	cipherTextTransposedBlocks := utils.TransposeByteSlice(cipherTextBytes, keySize)

	var key []byte
	for currentBlockIndex := range cipherTextTransposedBlocks {
		keyByte, _, _ := utils.DecryptSingleByteXor(cipherTextTransposedBlocks[currentBlockIndex])
		key = append(key, keyByte)
	}
	plainText := utils.RepeatingXor(cipherTextBytes, key)
	fmt.Println("Key:", string(key))
	fmt.Println("Plain text:", string(plainText))
}

// 7
func q7() {
	cipherTextSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/7.txt")
	cipherTextJoined := bytes.Join(cipherTextSlices, []byte(""))
	cipherTextBytes, err := base64.StdEncoding.DecodeString(string(cipherTextJoined))
	handleError(err)
	cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	handleError(err)
	cipherTextBlocks := chunkSlice(cipherTextBytes, 16)
	var plainTextBlocks [][]byte

	for i := range cipherTextBlocks {
		currentPlainTextBlock := make([]byte, 16)
		cipher.Decrypt(currentPlainTextBlock, cipherTextBlocks[i])
		plainTextBlocks = append(plainTextBlocks, currentPlainTextBlock)
	}

	plainText := bytes.Join(plainTextBlocks, []byte(""))
	fmt.Println(string(plainText))

	// fmt.Println(len(plainTextBlocks[0]))
}

// 8
func q8() {
	cipherTextSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/8.txt")
	var bytesFromHex [][]byte
	for _, currentSlice := range cipherTextSlices {
		currentByteSlice, err := hex.DecodeString(string(currentSlice))
		handleError(err)
		bytesFromHex = append(bytesFromHex, currentByteSlice)
	}
	var chosenBytes []byte
	for _, currentSlice := range bytesFromHex {
		currentChunks := chunkSlice(currentSlice, 16)
		for j, currentChunk := range currentChunks {
			for k, otherChunk := range currentChunks[j+1:] {
				if slices.Equal(currentChunk, otherChunk) {
					chosenBytes = currentSlice
					fmt.Println(j)
					fmt.Println(k + j + 1)
					fmt.Println(currentChunk)
					fmt.Println(otherChunk)
				}
			}
		}
	}
	fmt.Println()
	for i, b := range chunkSlice(chosenBytes, 16) {
		fmt.Println(i)
		fmt.Println(b)
	}
}

func main() {
	q6()
}

// helper functions
func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}

func meanSquareError(dict0, dict1 map[byte]float64) float64 {
	var sumSquaredErr float64 = 0
	for k, _ := range dict0 {
		diff := float64(dict1[k] - dict0[k])
		sumSquaredErr += float64(math.Pow(diff, 2))
	}
	meanSquareErr := sumSquaredErr / float64(len(dict0))
	return meanSquareErr
}

func xorBytesByByte(cipherText []byte, c byte) []byte {
	res := make([]byte, len(cipherText), len(cipherText))
	for i, b := range cipherText {
		res[i] = b ^ c
	}
	return res
}

func resetBytesFreqMap(byteFreqMap *map[byte]float64) {
	for k, _ := range *byteFreqMap {
		(*byteFreqMap)[k] = 0
	}
}

func fillBytesFreqMap(byteFreqMap *map[byte]float64, bytes []byte) {
	resetBytesFreqMap(byteFreqMap)
	for _, b := range bytes {
		(*byteFreqMap)[b] += float64(1) / float64(len(bytes))
	}
}

func decryptSingleXor(cipherText []byte) (float64, byte, string) {
	bytesFreqMap := make(map[byte]float64)
	var MSE float64 = 1
	var key byte
	var plainText string
	for i := 0; i < 128; i++ {
		testPlainText := bytes.ToUpper(xorBytesByByte(cipherText, byte(i)))
		fillBytesFreqMap(&bytesFreqMap, testPlainText)
		currentMSE := meanSquareError(resources.EngCharFreqMap, bytesFreqMap)
		if currentMSE < MSE {
			MSE = currentMSE
			key = byte(i)
			plainText = string(testPlainText)
		}
	}
	return MSE, key, plainText
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

func hammingDistance(byteSlc0, byteSlc1 []byte) int {
	if len(byteSlc0) != len(byteSlc1) {
		panic("Undefined for inputs of unequal length")
	}
	var count int
	for i := range byteSlc0 {
		xor := byteSlc0[i] ^ byteSlc1[i]
		for x := xor; x > 0; x >>= 1 {
			if (x & 1) == 1 {
				count++
			}
		}
	}
	return count
}

func findKeySize(cipherText []byte) int {
	var minNormDistance float64 = math.Inf(1)
	var keySize int
	for i := 2; i < 41; i++ {
		var testBlocks [][]byte

		for j := i; j < len(cipherText); {
			testBlocks = append(testBlocks, cipherText[j-i:j])
			j += i
		}
		var normDistanceSum float64
		var normDistanceAvg float64
		for j := 0; j < len(testBlocks)-2; j++ {
			for k := range testBlocks[j+1:] {
				normDistanceSum += float64(hammingDistance(testBlocks[j], testBlocks[k])) / float64(i)
			}
		}
		normDistanceAvg = normDistanceSum / float64(combin.Binomial(len(testBlocks), 2))
		if normDistanceAvg < minNormDistance {
			minNormDistance = normDistanceAvg
			keySize = i
		}
	}
	return keySize
}

func chunkSlice[T any](slice []T, chunkSize int) [][]T {
	var chunks [][]T
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}
