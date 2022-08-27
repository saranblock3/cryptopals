package aesecb

import (
	"bytes"
	"crypto/aes"
	"github.com/saranblock3/cryptopals/pkg/utils"
)

func Encrypt(plainText []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	plainTextBlocks := utils.ChunkSlice(plainText, 16)
	var cipherTextBlocks [][]byte
	for currentBlockIndex := range plainTextBlocks {
		currentCipherTextBlock := make([]byte, 16)
		cipher.Encrypt(currentCipherTextBlock, plainTextBlocks[currentBlockIndex])
		cipherTextBlocks = append(cipherTextBlocks, currentCipherTextBlock)
	}
	cipherText := bytes.Join(cipherTextBlocks, []byte(""))
	return cipherText
}

func Decrypt(cipherText []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	cipherTextBlocks := utils.ChunkSlice(cipherText, 16)
	var plainTextBlocks [][]byte
	for currentBlockIndex := range cipherTextBlocks {
		currentPlainTextBlock := make([]byte, 16)
		cipher.Decrypt(currentPlainTextBlock, cipherTextBlocks[currentBlockIndex])
		plainTextBlocks = append(plainTextBlocks, currentPlainTextBlock)
	}
	plainText := bytes.Join(plainTextBlocks, []byte(""))
	return plainText
}
