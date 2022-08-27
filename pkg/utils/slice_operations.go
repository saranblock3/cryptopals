package utils

import ()

// Cuts up a slice into chunks of a specified size and returns a slice of these chunks
func ChunkSlice[T any](slice []T, chunkSize int) [][]T {
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

// Tranposes a byte slice by grouping each nth element
func TransposeByteSlice(byteSlice []byte, numBlocks int) [][]byte {
	transposedBlocks := make([][]byte, numBlocks, numBlocks)
	for currentBlockIndex := range transposedBlocks {
		var currentBlock []byte
		for currentByteIndex, currentByte := range byteSlice {
			if currentByteIndex%numBlocks == currentBlockIndex {
				currentBlock = append(currentBlock, currentByte)
			}
		}
		transposedBlocks[currentBlockIndex] = currentBlock
	}
	return transposedBlocks
}

func HammingDistance(byteSlc0, byteSlc1 []byte) int {
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
