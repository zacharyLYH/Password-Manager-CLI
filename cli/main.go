package main

import (
	"crypto/rsa"
	"fmt"
	"time"
)

type DesktopCreds struct {
	SymKey      []byte
	ServerPub   *rsa.PublicKey
	Username    string
	Ttl         time.Time
	DesktopPub  *rsa.PublicKey
	DesktopPriv *rsa.PrivateKey
}

type Input struct {
	Operation       string
	AccountUsername string
	AccountPassword string
	SiteUsername    string
	SitePassword    string
	Description     string
	Err             string
	DocID           string
}

type SendServer struct {
	SecretSym       []byte
	Msg             []byte
	AccountUsername string
	AccountPassword []byte
	Description     string
	Hash            []byte
	DesktopPub      *rsa.PublicKey
	SecretMsg       []byte
	SiteUsername    []byte
	SitePassword    []byte
	DocID           string
}

type ServerResponse struct {
	SecretMsg    []byte
	Msg          []byte
	SecretSym    []byte
	Status       string
	SiteUsername []byte
	SitePassword []byte
}

type AllPasswords struct {
	DocID       string `bson:"DocID"`
	Description string `bson:"Description"`
}

func main() {
	createKeyAndSave()
	C := DesktopCreds{
		[]byte{}, //32
		extractPubKey(pwd() + "/serverPublic.pem"),
		"",
		time.Now(),
		extractPubKey(pwd() + "/desktopPublic.pem"),
		extractPrivKey(pwd() + "/desktopPrivate.pem"),
	}
	welcomePage()
	var input Input
	var command string
	for {
		command = readUserInput()
		parseInput(&input, command)
		if input.Operation == "signup" {
			if C.Username != "" {
				fmt.Println("Already logged in please exit first")
				continue
			}
			signup(&C, input)
		}
		if input.Operation == "exit" {
			gracefulExit(&C)
		}
		if input.Operation == "testRSA" {
			testRSAConnection()
		}
		if input.Operation == "ping" {
			testConnection()
		}
		if input.Operation == "login" {
			if C.Username != "" {
				fmt.Println("Already logged in")
				continue
			}
			login(&C, input)
		}
		if input.Operation == "new" {
			createPasswordEntry(&C, input)
		}
		if input.Operation == "getall" {
			getAllEntries(&C)
		}
		if input.Operation == "getone" {
			getOnePassword(&C, input)
		}
		if input.Operation == "update" {
			updatePassword(&C, input)
		}
		if input.Operation == "delete" {
			deletePassword(&C, input)
		}
	}
}
