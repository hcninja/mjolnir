package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	jwtFlag := flag.String("jwt", "", "The JWT token")
	dicFlag := flag.String("dict", "", "The password dictionary")
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	if *jwtFlag == "" || *dicFlag == "" {
		flag.Usage()
		return
	}

	log.Println("\n[*] Starting Mjölnir the JWT hammer.")

	jwtArr := strings.Split(*jwtFlag, ".")

	if len(jwtArr) != 3 {
		log.Fatal("[!] Not a JWT token")
		return
	}

	header, _ := jwt.DecodeSegment(jwtArr[0])
	data, _ := jwt.DecodeSegment(jwtArr[1])
	signature, _ := jwt.DecodeSegment(jwtArr[2])

	log.Printf("[+] Header:    %s", header)
	log.Printf("[+] Data:      %s", data)
	log.Printf("[+] Signature: %x", signature)

	// Set the payload
	payload := jwtArr[0] + "." + jwtArr[1]
	log.Printf("[+] Payload:  %s", payload)

	// Load password dictionary
	log.Println("[*] Loading dictionary")
	file, err := ioutil.ReadFile(*dicFlag)
	if err != nil {
		log.Fatalf("[!] %s", err.Error())
	}
	passwds := strings.Split(string(file), "\n")

	// Bruteforce the password
	then := time.Now()

	var passOk string
	log.Println("[*] Starting bruteforce, this can be slow, be patient")
	for _, pwd := range passwds {
		if hs256Calculator([]byte(payload), signature, []byte(pwd)) {
			passOk = pwd
			break
		}
	}

	now := time.Now().Sub(then).String()
	if passOk != "" {
		log.Printf("[!] Key found in %s, the key is %s", now, passOk)
	} else {
		log.Printf("[!] Password not found after running for %s :(", now)
	}
}

func hs256Calculator(payload, signature, password []byte) bool {
	mac := hmac.New(sha256.New, password)
	mac.Write(payload)
	newhmac := mac.Sum(nil)

	return bytes.Compare(signature, newhmac) == 0
}
