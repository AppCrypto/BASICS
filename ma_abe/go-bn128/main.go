package main

import (
	"crypto/rand"
	"example.com/m/abe"
	"example.com/m/bn128"
	"fmt"
	//"github.com/fentec-project/bn256"
	//"github.com/fentec-project/gofe/abe"
	"strconv"
	"time"
)

func main() {
	maabe := abe.NewMAABE()
	maabe.Test()
	const n int = 1000
	//t := 10
	attribs := [n][]string{}
	auths := [n]*abe.MAABEAuth{}
	keys := [n][]*abe.MAABEKey{}

	ks1 := []*abe.MAABEKey{} // ok

	for i := 0; i < n; i++ {
		authi := "auth" + strconv.Itoa(i)
		attribs[i] = []string{authi + ":at1"}
		// create three authorities, each with two attributes
		auths[i], _ = maabe.NewMAABEAuth("auth1", attribs[i])

	}

	// create a msp struct out of the boolean formula
	policyStr := ""
	for i := 0; i < n-1; i++ {
		authi := "auth" + strconv.Itoa(i)
		policyStr = authi + ":at1 AND "
	}
	policyStr += "auth" + strconv.Itoa(n-1) + ":at1"
	//msp, err := abe.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth4:at1", false)

	// define the set of all public keys we use
	pks := []*abe.MAABEPubKey{}
	for i := 0; i < n; i++ {
		pks = append(pks, auths[i].PubKeys())
	}

	// choose a message
	//msg := "Attack at dawn!"
	//var bt bytes.Buffer
	//for i := 0; i < 1024*1024; i++ {
	//	bt.WriteString(" Attack at dawn!")
	//}
	//msg := bt.String()

	//msg := "Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!Attack at dawn!"
	startts := time.Now().UnixNano() / 1e3
	var ct *abe.MAABECipher
	// encrypt the message with the decryption policy in msp
	_, symKey, _ := bn128.RandomGT(rand.Reader)
	msg := symKey
	msp, _ := abe.BooleanToMSP(policyStr, false)
	for i := 0; i < 100; i++ {
		ct, _ = maabe.Encrypt2(symKey, msp, pks)
	}
	endts := time.Now().UnixNano() / 1e3
	//if err != nil {
	//	fmt.Println("Failed to encrypt: %v\n", err)
	//}
	fmt.Printf("%d nodes encrypt time cost: %v μs\n", n, (endts-startts)/100)
	// choose a single user's Global ID
	gid := "gid1"

	startts = time.Now().UnixNano() / 1e3
	for i := 0; i < 100; i++ {
		auths[0].GenerateAttribKeys(gid, attribs[0])
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes keygen time cost: %v μs\n", n, (endts-startts)/100)
	for i := 0; i < n; i++ {
		keys[i], _ = auths[i].GenerateAttribKeys(gid, attribs[i])
		ks1 = append(ks1, keys[i][0])
	}
	startts = time.Now().UnixNano() / 1e3
	var msg1 *bn128.GT
	for i := 0; i < 100; i++ {
		msg1, _ = maabe.Decrypt2(ct, ks1)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes decrypt time cost: %v μs\n", n, (endts-startts)/100)
	fmt.Println(msg.String() == msg1.String())
	//fmt.Println(msg1)

}
