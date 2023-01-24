package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

func welcomePage() {
	fmt.Println("Welcome to password manager")
}

func testRSAConnection() {
	C := DesktopCreds{
		[]byte{}, //32
		extractPubKey(pwd() + "/serverPublic.pem"),
		"",
		time.Now(),
		extractPubKey(pwd() + "/desktopPublic.pem"),
		extractPrivKey(pwd() + "/desktopPrivate.pem"),
	}
	var send SendServer
	send.SecretMsg = encryptRSA(C.ServerPub, []byte("Hello"))
	send.DesktopPub = C.DesktopPub
	jsonData, _ := json.Marshal(send)
	response := post(jsonData, "http://localhost:8000/testRSAConnection")
	var serverRes ServerResponse
	json.Unmarshal(response, &serverRes)
	res := decryptRSA(serverRes.SecretMsg, C.DesktopPriv)
	fmt.Println(string(res))
}

func testConnection() {
	C := DesktopCreds{
		[]byte{}, //32
		extractPubKey(pwd() + "/serverPublic.pem"),
		"",
		time.Now(),
		extractPubKey(pwd() + "/desktopPublic.pem"),
		extractPrivKey(pwd() + "/desktopPrivate.pem"),
	}
	var send SendServer
	send.DesktopPub = C.DesktopPub
	jsonData, _ := json.Marshal(send)
	response := post(jsonData, "http://localhost:8000/askForSym")
	var serverRes ServerResponse
	json.Unmarshal(response, &serverRes)
	C.SymKey = decryptRSA(serverRes.SecretSym, C.DesktopPriv)
	var testPrint SendServer
	testPrint.Hash = encryptAES([]byte("Connection"), C.SymKey)
	jsonData, _ = json.Marshal(testPrint)
	response = post(jsonData, "http://localhost:8000/checkAESConnection")
	var encrypted ServerResponse
	json.Unmarshal(response, &encrypted)
	rawMsg := decryptAES(C.SymKey, encrypted.Msg)
	fmt.Println(rawMsg)
}

func signup(C *DesktopCreds, input Input) {
	uniqueUsername := ""
	for uniqueUsername == "" {
		fmt.Println("*********\nProvide a username")
		var send SendServer
		send.AccountUsername = readUserInput()
		if send.AccountUsername == "exit" {
			os.Exit(0)
		}
		jsonData, _ := json.Marshal(send)
		resp := post(jsonData, "http://localhost:8000/checkIfUsernameAvailable")
		var serverRes ServerResponse
		json.Unmarshal(resp, &serverRes)
		fmt.Println(string(serverRes.Msg))
		if serverRes.Status == "success" {
			uniqueUsername = send.AccountUsername
		}
	}
	var send SendServer
	send.AccountUsername = uniqueUsername
	fmt.Println("*********\nProvide a secure password") //add validity checks
	userinput := readUserInput()
	if len(userinput) < 1{
		fmt.Println("Password is too short")
		return
	}
	send.AccountPassword = encryptRSA(C.ServerPub, []byte(userinput))
	jsonData, _ := json.Marshal(send)
	response := post(jsonData, "http://localhost:8000/signup")
	var resp ServerResponse
	json.Unmarshal(response, &resp)
	fmt.Println(string(resp.Msg))
}

func login(C *DesktopCreds, input Input) {
	var send SendServer
	send.AccountUsername = input.AccountUsername
	send.AccountPassword = encryptRSA(C.ServerPub, []byte(input.AccountPassword))
	send.DesktopPub = C.DesktopPub
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/login")
	var serverRes ServerResponse
	json.Unmarshal(resp, &serverRes)
	if serverRes.Status == "Authenticated" {
		C.Ttl = time.Now().Add(time.Minute * 20)
		C.Username = input.AccountUsername
		C.SymKey = decryptRSA(serverRes.SecretSym, C.DesktopPriv)
		fmt.Println("Logged in")
	} else {
		fmt.Println("Not logged in")
	}
}

func createPasswordEntry(C *DesktopCreds, input Input) {
	checkttl(C)
	var send SendServer
	send.SiteUsername = encryptAES([]byte(input.SiteUsername), C.SymKey)
	send.SitePassword = encryptAES([]byte(input.SitePassword), C.SymKey)
	send.Description = input.Description
	send.AccountUsername = C.Username
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/createPasswordEntry")
	var serverRes ServerResponse
	json.Unmarshal(resp, &serverRes)
	fmt.Println(serverRes.Status)
}

func getAllEntries(C *DesktopCreds) {
	checkttl(C)
	var send SendServer
	send.AccountUsername = C.Username
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/getAllPasswords")
	var passes []AllPasswords
	json.Unmarshal(resp, &passes)
	sort.Slice(passes, func(i, j int) bool {
		num1, _ := strconv.Atoi(passes[i].DocID)
		num2, _ := strconv.Atoi(passes[j].DocID)
		return num1 < num2
	})
	fmt.Println("DocID			Description")
	for i := 0; i < len(passes); i++ {
		fmt.Println(passes[i].DocID + "\t\t\t" + passes[i].Description)
	}
}

func getOnePassword(C *DesktopCreds, input Input) {
	checkttl(C)
	var send SendServer
	send.DocID = input.DocID
	send.AccountUsername = C.Username
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/getOnePassword")
	var response ServerResponse
	json.Unmarshal(resp, &response)
	username := decryptAES(C.SymKey, response.SiteUsername)
	password := decryptAES(C.SymKey, response.SitePassword)
	fmt.Println(username + "\t" + password + "\t" + string(response.Msg))
}

func updatePassword(C *DesktopCreds, input Input) {
	checkttl(C)
	var send SendServer
	send.DocID = input.DocID
	send.AccountUsername = C.Username
	if input.SiteUsername != "" {
		send.SiteUsername = encryptAES([]byte(input.SiteUsername), C.SymKey)
	}
	if input.SitePassword != "" {
		send.SitePassword = encryptAES([]byte(input.SitePassword), C.SymKey)
	}
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/updatePassword")
	var response ServerResponse
	json.Unmarshal(resp, &response)
	fmt.Println(string(response.Msg))
}

func deletePassword(C *DesktopCreds, input Input) {
	checkttl(C)
	var send SendServer
	send.DocID = input.DocID
	send.AccountUsername = C.Username
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/deletePassword")
	var response ServerResponse
	json.Unmarshal(resp, &response)
	fmt.Println(string(response.Msg))
}

func checkttl(C *DesktopCreds) {
	if C.Username == "" {
		fmt.Println("Attempting to access authorized route without logging in.")
	}
	if C.Ttl != time.Now() {
		return
	}
	gracefulExit(C)
}

func gracefulExit(C *DesktopCreds) {
	C.ServerPub = nil
	var send SendServer
	send.AccountUsername = C.Username
	send.SecretSym = C.SymKey
	C.SymKey = nil
	C.Username = ""
	jsonData, _ := json.Marshal(send)
	resp := post(jsonData, "http://localhost:8000/clearSymMap")
	var serverRes ServerResponse
	json.Unmarshal(resp, &serverRes)
	fmt.Println(serverRes.Status)
	os.Exit(0)
}
