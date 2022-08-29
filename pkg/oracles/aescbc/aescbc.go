package aescbc

import (
	"github.com/saranblock3/cryptopals/pkg/oracles/aesecb"
	"github.com/saranblock3/cryptopals/pkg/utils"
)

func Encrypt(plainText []byte, key []byte) []byte {
	var cipherText []byte
	var lastBlock []byte
	iv := make([]byte, 16, 16)
	plainTextBlocks := utils.ChunkSlice(plainText, 16)
	for i, currentBlock := range plainTextBlocks {
		if i == 0 {
			lastBlock = iv
		}
		currentPaddedBlock, _ := utils.Pkcs7Padding(currentBlock, 16)
		currentXorText, _ := utils.XorByteSlice(currentPaddedBlock, lastBlock)
		currentCipherTextBlock := aesecb.Encrypt(currentXorText, key)
		cipherText = append(cipherText, currentCipherTextBlock...)
		lastBlock = currentCipherTextBlock
	}
	return cipherText
}

func Decrypt(cipherText []byte, key []byte) []byte {
	var plainText []byte
	var lastBlock []byte
	iv := make([]byte, 16, 16)
	cipherTextBlocks := utils.ChunkSlice(cipherText, 16)
	for i, currentBlock := range cipherTextBlocks {
		if i == 0 {
			lastBlock = iv
		}
		currentXorText := aesecb.Decrypt(currentBlock, key)
		currentPlainTextBlock, _ := utils.XorByteSlice(currentXorText, lastBlock)
		plainText = append(plainText, currentPlainTextBlock...)
		lastBlock = currentBlock
	}
	return plainText
}
