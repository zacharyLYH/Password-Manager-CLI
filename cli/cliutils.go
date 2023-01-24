package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crytpRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func createKeyAndSave() {
	privatekey, err := rsa.GenerateKey(crytpRand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create("desktopPrivate.pem")
	if err != nil {
		fmt.Printf("error when create userPrivate.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode Private pem: %s \n", err)
		os.Exit(1)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("desktopPublic.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
}

func decryptRSA(encryptedBytes []byte, privateKey *rsa.PrivateKey) []byte {
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return decryptedBytes
}

func encryptRSA(publicKey *rsa.PublicKey, payload []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		crytpRand.Reader,
		publicKey,
		payload,
		nil)
	if err != nil {
		panic(err)
	}
	return encryptedBytes
}

func encryptAES(text, key []byte) []byte {
	c, err := aes.NewCipher(key)

	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crytpRand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	return gcm.Seal(nonce, nonce, text, nil)
}

func decryptAES(key, ciphertext []byte) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return string(plaintext)
}

func extractPubKey(location string) *rsa.PublicKey {
	key, err := ioutil.ReadFile(location)
	if err != nil {
		fmt.Println(err)
	}
	pemBlock, _ := pem.Decode(key)
	parseResult, _ := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	return parseResult.(*rsa.PublicKey)
}

func extractPrivKey(location string) *rsa.PrivateKey {
	key, err := ioutil.ReadFile(location)
	if err != nil {
		fmt.Println(err)
	}
	pemBlock, _ := pem.Decode(key)
	parseResult, _ := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	return parseResult
}

func post(data []byte, httpposturl string) []byte {
	request, _ := http.NewRequest("POST", httpposturl, bytes.NewBuffer(data))
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		panic(error)
	}
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	return body
}

func readUserInput() string {
	fmt.Print("::::: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan() // use `for scanner.Scan()` to keep reading
	line := scanner.Text()
	return line
}

func parseInput(input *Input, command string) {
	split := strings.Split(command, " ")
	if split[0] == "signup" {
		input.Operation = "signup"
		input.AccountUsername = ""
		input.AccountPassword = ""
		return
	}
	if split[0] == "test" {
		input.Operation = "test"
		return
	}
	if split[0] == "getall" {
		input.Operation = "getall"
		return
	}
	if split[0] == "exit" {
		input.Operation = "exit"
		return
	}
	if split[0] == "testRSA" {
		input.Operation = "testRSA"
		return
	}
	if split[0] == "getone" {
		input.Operation = "getone"
		input.DocID = split[1]
		return
	}
	if split[0] == "ping" {
		input.Operation = "ping"
		return
	}
	if split[0] == "new" {
		input.Operation = "new"
		input.SiteUsername = split[1]
		input.SitePassword = split[2]
		input.Description = split[3]
		return
	}
	if split[0] == "login" {
		if len(split) != 3 {
			fmt.Println("Format: login username password")
			return
		}
		input.Operation = "login"
		input.AccountUsername = split[1]
		input.AccountPassword = split[2]
		return
	}
	if split[0] == "update" {
		input.Operation = "update"
		input.DocID = split[1]
		if len(split) == 4 {
			input.SiteUsername = split[2]
			input.SitePassword = split[3]
		} else {
			input.SitePassword = split[2]
		}
		return
	}
	if split[0] == "delete" {
		input.Operation = "delete"
		input.DocID = split[1]
		return
	}
	fmt.Println("Not a command")
}

func pwd() string {
	mydir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	return mydir
}
