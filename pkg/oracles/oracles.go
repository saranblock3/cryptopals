package oracles

import (
	"fmt"
	"github.com/saranblock3/cryptopals/pkg/oracles/aescbc"
	"github.com/saranblock3/cryptopals/pkg/oracles/aesecb"
	"github.com/saranblock3/cryptopals/pkg/utils"
	"math/rand"
	"time"
)

func EcbCbcEncryptionOracle(plainText []byte) []byte {
	paddedPlainText := utils.RandomWrapPadding(plainText)
	rand.Seed(time.Now().UnixNano())
	randomChooser := rand.Intn(2)
	key, _ := utils.GenerateRandomKey(16)
	fmt.Println(key)
	var cipherText []byte

	switch randomChooser {
	case 0:
		cipherText = aesecb.Encrypt(paddedPlainText, key)
		fmt.Println("ECB mode")
	case 1:
		cipherText = aescbc.Encrypt(paddedPlainText, key)
		fmt.Println("CBC mode")
	}

	return cipherText
}

func EcbCbcDetectionOracle(cipherText []byte) int {
	if utils.IsEcbEncrypted(cipherText) {
		return 0
	} else {
		return 1
	}
}
