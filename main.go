package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gpwd [enc|dec]")
		return
	}

	action := os.Args[1]
	switch action {
	case "enc":
		encryptPassword()
	case "dec":
		decryptPassword()
	default:
		fmt.Println("Usage: gpwd [enc|dec]")
	}
}

func encryptPassword() {
	secret := prompt("Enter secret: ")
	password := prompt("Enter password to encrypt: ")

	encrypted, err := encrypt([]byte(secret), password)
	if err != nil {
		fmt.Println("Error encrypting password:", err)
		return
	}

	fmt.Println("Encrypted password:", encrypted)
}

func decryptPassword() {
	secret := prompt("Enter secret: ")
	encrypted := prompt("Enter encrypted password: ")

	decrypted, err := decrypt([]byte(secret), encrypted)
	if err != nil {
		fmt.Println("Error decrypting password:", err)
		return
	}

	fmt.Println("Decrypted password:", decrypted)
}

func encrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	b := base64.StdEncoding.EncodeToString([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	data, _ := base64.StdEncoding.DecodeString(string(ciphertext))
	return string(data), nil
}

func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}
