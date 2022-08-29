package utils

import (
	"bytes"
	cryptorand "crypto/rand"
	"errors"
	"github.com/saranblock3/cryptopals/resources"
	"golang.org/x/exp/slices"
	"gonum.org/v1/gonum/stat/combin"
	"math"
	"math/rand"
	"time"
)

// Performs bitwise xor on two byte slices and returns the result (with an error)
func XorByteSlice(byteSlice0, byteSlice1 []byte) ([]byte, error) {
	// if slices not equal length return error
	if len(byteSlice0) != len(byteSlice1) {
		return nil, errors.New("Length of Slices not equal!")
	}
	resSlice := make([]byte, len(byteSlice0), len(byteSlice0))
	// xor corresponding byte from each slice
	for idx := range byteSlice0 {
		resSlice[idx] = byteSlice0[idx] ^ byteSlice1[idx]
	}
	return resSlice, nil
}

// Decrypts cipher text that has been XORed against a single byte
// and return the key, the plain text and the mse between the english
// letter frequency and the plain text letter frequency
func DecryptSingleByteXor(cipherText []byte) (byte, string, float64) {
	// byte frequency for the each 'plain text' after each decryption
	bytesFreqMap := make(map[byte]float64)
	// initialize final variables
	var mse float64 = math.Inf(1)
	var key byte
	var plainText string
	// loop through range of possible keys
	for currentKey := 0; currentKey < 256; currentKey++ {
		// the so called plain text for the current key
		testPlainText := bytes.ToUpper(XorBytesByByte(cipherText, byte(currentKey)))
		// populate the byte frequency map with the current plain text
		FillBytesFreqMap(&bytesFreqMap, testPlainText)
		// get the mean square error between the current byte frequency
		// map and the english letter frequency map
		currentMse := MeanSquareError(resources.EngCharFreqMap, bytesFreqMap)
		// find the lowest mse value and update the other variables
		if currentMse < mse {
			mse = currentMse
			key = byte(currentKey)
			plainText = string(testPlainText)
		}
	}
	return key, plainText, mse
}

// Returns the result of byte slice XORed by a single byte
func XorBytesByByte(cipherText []byte, key byte) []byte {
	resByteSlice := make([]byte, len(cipherText), len(cipherText))
	for idx, currentByte := range cipherText {
		resByteSlice[idx] = currentByte ^ key
	}
	return resByteSlice
}

// Returns the result of using a repeating key xor on a piece of cipher/plain text
func RepeatingXor(inputText []byte, key []byte) []byte {
	outputText := make([]byte, len(inputText), len(inputText))
	for i, currentByte := range inputText {
		outputText[i] = currentByte ^ key[i%len(key)]
	}
	return outputText
}

// Finds the key size of a repeating key xor on a piece of cipher text
func FindKeySize(cipherText []byte) int {
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
				normDistanceSum += float64(HammingDistance(testBlocks[j], testBlocks[k])) / float64(i)
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

// Finds the key in a repeating key xor of some cipher text
func FindRepeatingXorKey(cipherText []byte, keySize int) []byte {
	cipherTextTransposedBlocks := TransposeByteSlice(cipherText, keySize)

	var key []byte
	for currentBlockIndex := range cipherTextTransposedBlocks {
		keyByte, _, _ := DecryptSingleByteXor(cipherTextTransposedBlocks[currentBlockIndex])
		key = append(key, keyByte)
	}
	return key
}

// Predicate testing if cipher text is ecb ecnrypted
func IsEcbEncrypted(cipherText []byte) bool {
	cipherTextChunks := ChunkSlice(cipherText, 16)
	for currentChunkIndex, currentChunk := range cipherTextChunks {
		for _, otherChunk := range cipherTextChunks[currentChunkIndex+1:] {
			if slices.Equal(currentChunk, otherChunk) {
				return true
			}
		}
	}
	return false
}

// Implements PKCS#7 padding on plain text
func Pkcs7Padding(plainText []byte, blockLength int) ([]byte, error) {
	paddingLength := blockLength - len(plainText)
	if paddingLength < 0 {
		return nil, errors.New("Block is larger than block size!")
	}
	var padding []byte
	for i := 0; i < paddingLength; i++ {
		paddingChunk := byte(paddingLength)
		padding = append(padding, paddingChunk)
	}
	paddedPlainText := append(plainText, padding...)
	return paddedPlainText, nil
}

func GenerateRandomKey(keyLength int) ([]byte, error) {
	key := make([]byte, keyLength)
	_, err := cryptorand.Read(key)
	return key, err
}

func RandomPrePadding(plainText []byte) []byte {
	var padding []byte
	rand.Seed(time.Now().UnixNano())
	paddingLength := rand.Intn(6) + 5
	for i := 0; i < paddingLength; i++ {
		padding = append(padding, byte(rand.Intn(256)))
	}
	paddedPlainText := append(padding, plainText...)
	return paddedPlainText
}

func RandomPostPadding(plainText []byte) []byte {
	var padding []byte
	rand.Seed(time.Now().UnixNano())
	paddingLength := rand.Intn(6) + 5
	for i := 0; i < paddingLength; i++ {
		padding = append(padding, byte(rand.Intn(256)))
	}
	paddedPlainText := append(plainText, padding...)
	return paddedPlainText
}

func RandomWrapPadding(plainText []byte) []byte {
	prePaddedPlainText := RandomPrePadding(plainText)
	paddedPlainText := RandomPostPadding(prePaddedPlainText)
	return paddedPlainText
}
