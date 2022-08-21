package main

import (
	"fmt"
	"math"
	"encoding/hex"
	"encoding/base64"
	"bytes"
	// "golang.org/x/exp/slices"
	"net/http"
	"io/ioutil"
)

// useful constants and variables

// 1
func q1() {
	s := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	bytesFromHex, err := hex.DecodeString(s)	
	handleError(err)
	res := base64.StdEncoding.EncodeToString(bytesFromHex)
	fmt.Println(res)
}

// 2
func q2() {
	s0 := "1c0111001f010100061a024b53535009181c"	
	s1 := "686974207468652062756c6c277320657965"
	b0, err0 := hex.DecodeString(s0)
	b1, err1 := hex.DecodeString(s1)
	handleError(err0)
	handleError(err1)
	var xorByteSlice []byte = make([]byte, len(b0), len(b0))
	for i := range b0 {
		xorByteSlice[i] = b0[i] ^ b1[i]
	}
	res := hex.EncodeToString(xorByteSlice)
	fmt.Println(res)
}

// 3
var engCharFreqMap = map[byte]float64{
	1: 0, 2: 0, 3: 0, 4: 0, 5: 0,
	6: 0, 7: 0, 8: 0, 9: 0, 10: 0,
	11: 0, 12: 0, 13: 0, 14: 0, 15: 0,
	16: 0, 17: 0, 18: 0, 19: 0, 20: 0,
	21: 0, 22: 0, 23: 0, 24: 0, 25: 0,
	26: 0, 27: 0, 28: 0, 29: 0, 30: 0,
	31: 0, 32: 0, 33: 0, 34: 0, 35: 0,
	36: 0, 37: 0, 38: 0, 39: 0, 40: 0,
	41: 0, 42: 0, 43: 0, 44: 0, 45: 0,
	46: 0, 47: 0, 48: 0, 49: 0, 50: 0,
	51: 0, 52: 0, 53: 0, 54: 0, 55: 0,
	56: 0, 57: 0, 58: 0, 59: 0, 60: 0,
	61: 0, 62: 0, 63: 0, 64: 0, 69: 0.127,
	84: 0.091, 65: 0.082, 79: 0.075, 73: 0.070, 78: 0.067,
	83: 0.063, 72: 0.061, 82: 0.060, 68: 0.043,	 76: 0.040,
	67: 0.028,	 85: 0.028, 77: 0.024, 87: 0.024, 70: 0.022,
	71: 0.020, 89: 0.020, 80: 0.019, 66: 0.015,  86: 0.0098,
	75: 0.0077, 74: 0.0015, 88: 0.0015, 81: 0.00095, 90: 0.00074,
	91: 0, 92: 0, 93: 0, 94: 0, 95: 0,
	96: 0, 97: 0, 98: 0, 99: 0, 100: 0,
	101: 0, 102: 0, 103: 0, 104: 0, 105: 0,
	106: 0, 107: 0, 108: 0, 109: 0, 110: 0,
	111: 0, 112: 0, 113: 0, 114: 0, 115: 0,
	116: 0, 117: 0, 118: 0, 119: 0, 120: 0,
	121: 0, 122: 0, 123: 0, 124: 0, 125: 0,
	126: 0, 127: 0,
}

func q3() {
	s := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bytesFromHex, err := hex.DecodeString(s)
	handleError(err)
	// bytesFreqMap := make(map[byte]float64)
	// var (
	// 	testPlainText []byte
	// 	MSE float64 = 1
	// 	key byte
	// )
	// for i := 0; i < 128; i++ {
	// 	testPlainText = bytes.ToUpper(xorBytesByByte(bytesFromHex, byte(i)))
	// 	fillBytesFreqMap(&bytesFreqMap, testPlainText)
	// 	currentMSE := meanSquareError(engCharFreqMap, bytesFreqMap)
	// 	if currentMSE < MSE {
	// 		MSE = currentMSE
	// 		key = byte(i)
	// 	}
	// }
	_, key, _ := decryptSingleXor(bytesFromHex)
	fmt.Println(key)
}

// 4
func q4() {
	cipherTextArray := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/4.txt")
	var (
		resString string
		lowestMSE float64 = 1
	)
	for _, s := range cipherTextArray {
		bytesFromHex, err := hex.DecodeString(string(s))
		handleError(err)
		bytesFreqMap := make(map[byte]float64)
		for j := 0; j < 128; j++ {
			testPlainText := bytes.ToUpper(xorBytesByByte(bytesFromHex, byte(j)))
			fillBytesFreqMap(&bytesFreqMap, testPlainText)
			currentMSE := meanSquareError(engCharFreqMap, bytesFreqMap)
			if currentMSE < lowestMSE {
				lowestMSE = currentMSE
				resString = string(testPlainText)
				fmt.Println(currentMSE)
			}
		}
	}
	fmt.Println(resString)
	// var finalMse float64 = 1
	// var finalPlainText string
	// for _, cipherText := range cipherTextArray {
	// 	currentMse, _, currentPlainText := decryptSingleXor(cipherText)
	// 	if currentPlainText == "NOWTHATTHEPARTYISJUMPING*\n" {
	// 		fmt.Println(currentPlainText)
	// 		fmt.Println(currentMse)
	// 		fmt.Println()
	// 	}
	// 	if currentMse < finalMse {
	// 		finalMse = currentMse
	// 		finalPlainText = currentPlainText
	// 	}
	// }
	// fmt.Println(finalPlainText)
}

// 5
func q5() {
	plainText := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	cipherText := make([]byte, len(plainText), len(plainText))
	for i, b := range plainText {
		cipherText[i] = b ^ key[i%len(key)]
	}
	fmt.Println(hex.EncodeToString(cipherText))
}

// 6
func q6() {
	cipherTextSlices := getByteSlicesFromUrl("https://cryptopals.com/static/challenge-data/6.txt")
	cipherTextJoined := bytes.Join(cipherTextSlices, []byte(""))
	cipherTextBytes, err := base64.StdEncoding.DecodeString(string(cipherTextJoined))
	fmt.Println(string(cipherTextBytes))
	handleError(err)
	keySize := findKeySize(cipherTextBytes)

	cipherTextTransposedBlocks := make([][]byte, keySize, keySize)
	for i := range cipherTextTransposedBlocks {
		var block []byte
		for j, b := range cipherTextBytes {
			if j%keySize == i {
				block = append(block, b)
			}
		}
		cipherTextTransposedBlocks[i] = block
	}

	var key []byte
	for i := range cipherTextTransposedBlocks {
		_, keyByte, _ := decryptSingleXor(cipherTextTransposedBlocks[i])
		key = append(key, keyByte)
	}

	plainText := make([]byte, len(cipherTextBytes), len(cipherTextBytes))
	for i, b := range cipherTextBytes {
		plainText[i] = b ^ key[i%keySize]
	}
	fmt.Println(string(plainText))
}

// 7
func q7() {
	
}

func main() {
	q6()
}


// helper functions
func handleError(err error) {
	if err != nil {
		fmt.Println("Error: %s", err.Error())
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
		(*byteFreqMap)[b] += float64(1)/float64(len(bytes))
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
		currentMSE := meanSquareError(engCharFreqMap, bytesFreqMap)
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
			if (x&1) == 1 {
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
		testBlocks := [][]byte{
			cipherText[:i],
			cipherText[i:2*i],
			cipherText[2*i:3*i],
			cipherText[3*i:4*i],
			cipherText[4*i:5*i],
			cipherText[5*i:6*i],
			cipherText[6*i:7*i],
			cipherText[7*i:8*i],
			cipherText[8*i:9*i],
			cipherText[9*i:10*i],
			cipherText[10*i:11*i],
			cipherText[11*i:12*i],
			cipherText[12*i:13*i],
			cipherText[13*i:14*i],
			cipherText[14*i:15*i],
			cipherText[15*i:16*i],
			cipherText[16*i:17*i],
			cipherText[17*i:18*i],
			cipherText[18*i:19*i],
			cipherText[19*i:20*i],
			cipherText[20*i:21*i],
			cipherText[21*i:22*i],
			cipherText[22*i:23*i],
			cipherText[23*i:24*i],
			cipherText[24*i:25*i],
			cipherText[25*i:26*i],
			cipherText[26*i:27*i],
			cipherText[27*i:28*i],
			cipherText[28*i:29*i],
			cipherText[29*i:30*i],
			cipherText[30*i:31*i],
			cipherText[31*i:32*i],
			cipherText[32*i:33*i],
			cipherText[33*i:34*i],
			cipherText[34*i:35*i],
			cipherText[35*i:36*i],
			cipherText[36*i:37*i],
			cipherText[37*i:38*i],
			cipherText[38*i:39*i],
			cipherText[39*i:40*i],
		}
		var normDistanceSum float64
		var normDistanceAvg float64
		for j := 0; j < len(testBlocks) - 2; j++ {
			for k := range testBlocks[j+1:] {
				normDistanceSum += float64(hammingDistance(testBlocks[j], testBlocks[k])) / float64(i)
			}
		}
		normDistanceAvg = normDistanceSum / float64(496)
		fmt.Println(i)
		fmt.Println(normDistanceAvg)
		fmt.Println()
		if normDistanceAvg < minNormDistance {
			minNormDistance = normDistanceAvg
			keySize = i
		}
	}
	return keySize
}