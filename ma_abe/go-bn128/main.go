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
	const n int = 100
	const times int64 = 100
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
		policyStr += authi + ":at1 AND "
	}
	policyStr += "auth" + strconv.Itoa(n-1) + ":at1"
	//fmt.Println(policyStr)
	//msp, err := abe.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth4:at1", false)

	// define the set of all public keys we use
	pks := []*abe.MAABEPubKey{}
	for i := 0; i < n; i++ {
		pks = append(pks, auths[i].PubKeys())
	}

	startts := time.Now().UnixNano() / 1e3
	var ct *abe.MAABECipher
	// encrypt the message with the decryption policy in msp
	_, symKey, _ := bn128.RandomGT(rand.Reader)
	//fmt.Println(symKey)
	msg := symKey
	msp, _ := abe.BooleanToMSP(policyStr, false)
	for i := 0; i < int(times); i++ {
		ct, _ = maabe.Encrypt2(symKey, msp, pks)
	}
	endts := time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes encrypt time cost: %v μs ct size:%v kB\n", n, (endts-startts)/times, len(ct.String())/1024)
	// choose a single user's Global ID
	gid := "gid1"

	startts = time.Now().UnixNano() / 1e3
	var key []*abe.MAABEKey
	for i := 0; i < int(times); i++ {
		key, _ = auths[0].GenerateAttribKeys(gid, attribs[0])
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes keygen time cost: %v μs key size:%v B\n", n, (endts-startts)/times, len(key[0].String()))
	for i := 0; i < n; i++ {
		keys[i], _ = auths[i].GenerateAttribKeys(gid, attribs[i])
		ks1 = append(ks1, keys[i][0])
	}
	startts = time.Now().UnixNano() / 1e3
	var msg1 *bn128.GT
	for i := 0; i < int(times); i++ {
		msg1, _ = maabe.Decrypt2(ct, ks1)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes decrypt time cost: %v μs\n", n, (endts-startts)/times)
	fmt.Println(msg.String() == msg1.String())
	//fmt.Println(msg1)

}
