package utils

import (
	"math"
)

// Calculates the mse for the values of two maps
func MeanSquareError(map0, map1 map[byte]float64) float64 {
	var sumSquaredErr float64 = 0
	for key, _ := range map0 {
		diff := float64(map1[key] - map0[key])
		sumSquaredErr += float64(math.Pow(diff, 2))
	}
	meanSquareErr := sumSquaredErr / float64(len(map0))
	return meanSquareErr
}

// Resets a map so all keys have value 0
func ResetByteFloatMap(inputMap *map[byte]float64) {
	for key, _ := range *inputMap {
		(*inputMap)[key] = 0
	}
}

// Fills in the frequency map values for each byte in bytes
func FillBytesFreqMap(byteFreqMap *map[byte]float64, bytes []byte) {
	ResetByteFloatMap(byteFreqMap)
	for _, b := range bytes {
		(*byteFreqMap)[b] += float64(1) / float64(len(bytes))
	}
}
