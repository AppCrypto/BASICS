package main

import (

	//"basics/ma_abe/bn128"

	"basics/crypto/rwdabe"
	"fmt"
	"strconv"
	"time"

	//"github.com/fentec-project/bn256"
	//"github.com/fentec-project/gofe/abe"

	lib "github.com/fentec-project/gofe/abe"
)

func main() {

	maabe := rwdabe.NewMAABE()

	const n int = 20
	const times int64 = 100
	attribs := [n][]string{}
	auths := [n]*rwdabe.MAABEAuth{}
	//keys := [n][]*rwdabe.MAABEKey{}

	ks1 := []*rwdabe.MAABEKey{} // ok

	for i := 0; i < n; i++ {
		authi := "auth" + strconv.Itoa(i)
		attribs[i] = []string{authi + ":at1"}
		// create three authorities, each with two attributes
		auths[i], _ = maabe.NewMAABEAuth(authi)
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
	pks := []*rwdabe.MAABEPubKey{}
	for i := 0; i < n; i++ {
		pks = append(pks, auths[i].Pk)
	}

	startts := time.Now().UnixNano() / 1e3
	var ct *rwdabe.MAABECipher
	// encrypt the message with the decryption policy in msp
	// _, symKey, _ := bn128.RandomGT(rand.Reader)
	//fmt.Println(symKey)
	msg := "Attack at dawn!"
	msp, _ := lib.BooleanToMSP(policyStr, false)
	for i := 0; i < int(times); i++ {
		ct, _ = maabe.ABEEncrypt(msg, msp, pks)
	}
	endts := time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes encrypt time cost: %v ms ct size:%v kB\n", n, (endts-startts)/times/1000, len(ct.String())/1024)
	// choose a single user's Global ID

	gid := "gid1"
	//fmt.Println(attribs[0])
	//fmt.Println("test")

	attribstest := []string{"auth1:at1"}
	startts = time.Now().UnixNano() / 1e3
	//var key []*abe.MAABEKey
	for i := 0; i < int(times); i++ {
		//var key []*abe.MAABEKey
		_, _ = auths[0].ABEKeyGen(gid, attribstest[0])
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes keygen time cost: %v μs \n", n, 2*(endts-startts)/times) //*2 due to LW CP-ABE

	for i := 0; i < n; i++ {
		keys, _ := auths[i].ABEKeyGen(gid, attribs[i][0])
		ks1 = append(ks1, keys)
	}
	//fmt.Println(ks1)
	startts = time.Now().UnixNano() / 1e3
	var msg1 string
	for i := 0; i < int(times); i++ {
		msg1, _ = maabe.ABEDecrypt(ct, ks1)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes decrypt time cost: %v ms\n", n, (endts-startts)/times/1000)
	fmt.Println(msg == msg1)

}
