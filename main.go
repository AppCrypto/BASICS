package main

import (
	"basics/compile/contract"
	"basics/crypto/rwdabe"
	"basics/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fentec-project/bn256"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"golang.org/x/crypto/sha3"
)

// data, err := json.Marshal(acjudges)
// print(data)
// data := `[
//
//	{"props": ["Alice", "Carl"], "acs": "Carl AND Alice"},
//	{"props": ["Alice", "Carl","Tom"], "acs": "Carl AND Alice AND Tom"},
//	{"props": ["Alice", "Bob", "Carl","Tom"], "acs": "Carl AND (Alice AND (Tom AND Bob))"},
//	{"props": ["Alice", "Bob", "Carl","Tom","Eve"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve"},
//	{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav"},
//	{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB"},
//	{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC"},
//	{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC","AD"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC AND AD"},
//	{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC","AD","AE"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC AND AD AND AE"},
//	{"props": ["Alice"], "acs": "Alice OR Carl"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR Tom"},
//	{"props": ["Alice"], "acs": "Carl OR (Alice OR (Tom OR Bob))"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD"},
//	{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD OR AE"}
//
// ]`
// var acjudges []ACJudge
// // 解码 JSON 数据
// err := json.Unmarshal([]byte(data), &acjudges)
//
//	if err != nil {
//		fmt.Println("Error decoding JSON:", err)
//		return
//	}
//
// fmt.Println("Decoded JSON data:")
type ACJudge struct {
	Props []string `json:"props"`
	ACS   string   `json:"acs"`
}

func randomInt(curveOrder *big.Int) *big.Int {
	// Generate a random number in [0, curve_order-1]
	n, err := rand.Int(rand.Reader, curveOrder)
	if err != nil {
		panic(err)
	}
	// Add 1 to shift to [1, curve_order]
	n.Add(n, big.NewInt(1))
	return n
}

// keccak256 computes the Keccak256 hash of the input data.
func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// hash2G1 hashes the input data to a point on the bn256 G1 curve.
func hash2G1(data []byte) *bn128.G1 {
	hash := keccak256(data)
	intHash := new(big.Int).SetBytes(hash)
	g1 := new(bn128.G1)
	g1.ScalarBaseMult(intHash)
	return g1
}

// hash2int converts the Keccak256 hash of the input data to an integer.
func hash2int(data []byte) *big.Int {
	hash := keccak256(data)
	intHash := new(big.Int).SetBytes(hash)
	return intHash
}

//// G1ToArr converts a G1 point to an array of big integers.
//func G1ToArr(g *bn128.G1) [2]*big.Int {
//	x, y := g.Unmarshal()
//	return [2]*big.Int{x, y}
//}
//
//// G2ToArr converts a G2 point to a nested array of big integers.
//func G2ToArr(g *bn128.G2) [2][2]*big.Int {
//	coeffs := g.Unmarshal()
//	a := G1ToArr(coeffs[0])
//	b := G1ToArr(coeffs[1])
//	return [2][2]*big.Int{{a[1], a[0]}, {b[1], b[0]}}
//}

func G1ToBigIntArray(point *bn256.G1) [2]*big.Int {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())
	//fmt.Println(g.Marshal())
	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	return [2]*big.Int{x, y}
}

func G2ToBigIntArray(point *bn256.G2) [2][2]*big.Int {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	return [2][2]*big.Int{{a1, a2}, {b1, b2}}
}

func testHash2G1() {
	data := []byte("data")

	// Compute Keccak256 hash
	hash := keccak256(data)
	fmt.Println("Keccak256 hash:", hex.EncodeToString(hash))

	// Convert hash to an integer
	intHash := new(big.Int).SetBytes(hash)
	fmt.Println("Keccak256 hash as int:", intHash)

	// Hash to G1
	g1Point := hash2G1(data)
	fmt.Println("G1 Point:", g1Point)
}
func generateACPStr(n int) *ACJudge {

	attrs := make([]string, n)
	for i := 1; i < n+1; i++ {
		attrs[i-1] = "auth" + strconv.Itoa(i) + ":at1"
		//fmt.Println(strconv.Itoa(i))
	}

	acp := utils.RandomACP(attrs)
	//fmt.Println(acp, attrs)
	return &ACJudge{ACS: acp, Props: attrs}
}

func main() {

	contract_name := "Basics"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

	address, _ := utils.Deploy(client, contract_name, deployTX)

	ctc, err := contract.NewContract(common.HexToAddress(address.Hex()), client)

	fmt.Println("...........................................................Setup............................................................")

	maabe := rwdabe.NewMAABE()

	// create  authorities, each with two attributes
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	attribs4 := []string{"auth4:at1", "auth4:at2"}
	auth1, _ := maabe.NewMAABEAuth("auth1")
	auth2, _ := maabe.NewMAABEAuth("auth2")
	auth3, _ := maabe.NewMAABEAuth("auth3")
	auth4, _ := maabe.NewMAABEAuth("auth4")

	//User Setup...(sk,pk)
	userSk := rwdabe.RandomInt()
	userPk := new(bn128.G1).ScalarMult(auth3.Maabe.G1, userSk)

	fmt.Println("..........................................................Encrypy...........................................................")

	acjudges := make([]*ACJudge, 1)
	acjudges[0] = generateACPStr(4)
	fmt.Println("Access Control Policy:", acjudges[0].ACS)
	//msp, _ := lib.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth3:at2 AND auth4:at1", false)
	msp, _ := lib.BooleanToMSP(acjudges[0].ACS, false)
	// define the set of all public keys we use
	pks := []*rwdabe.MAABEPubKey{auth1.Pk, auth2.Pk, auth3.Pk, auth4.Pk}

	// choose a message
	msg := "Attack at dawn!"

	// encrypt the message with the decryption policy in msp
	ct, _ := maabe.ABEEncrypt(msg, msp, pks)

	fmt.Println("..........................................................Request...........................................................")

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user
	key11, _ := auth1.ABEKeyGen(gid, attribs1[0])
	key12, _ := auth1.ABEKeyGen(gid, attribs1[1])
	// authority 2 issues keys to user
	key21, _ := auth2.ABEKeyGen(gid, attribs2[0])
	key22, _ := auth2.ABEKeyGen(gid, attribs2[1])
	// authority 4 issues keys to user
	key41, _ := auth4.ABEKeyGen(gid, attribs4[0])
	key42, _ := auth4.ABEKeyGen(gid, attribs4[1])

	// authority 3 issues keys to user
	//key31, err := auth3.ABEKeyGen(gid, attribs3[0])
	key31Enc, _ := auth3.ABEKeyGen(gid, attribs3[0], userPk)
	proof31, _ := auth3.KeyGenPrimeAndGenProofs(key31Enc, userPk)

	key32Enc, _ := auth3.ABEKeyGen(gid, attribs3[1], userPk)
	proof32, _ := auth3.KeyGenPrimeAndGenProofs(key32Enc, userPk)

	fmt.Println("...........................................................Verify...........................................................")
	//CheckKey1  off-chain (3 eq)
	res31, err := maabe.CheckKey(userPk, key31Enc, proof31)
	res32, err := maabe.CheckKey(userPk, key32Enc, proof32)
	fmt.Println("offchain Checkkey result:", res31, res32)
	//fmt.Println("userPK:", userPk)
	//fmt.Println("Key31Enc:", key31Enc)
	//fmt.Println("proof31:", proof31)
	//fmt.Println(G1ToBigIntArray(userPk))
	//fmt.Println(G2ToBigIntArray(proof31.G2ToAlpha))

	//CheckKey2 on-chain (4 eq)
	auth0 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx1, _ := ctc.PKtoSC(auth0, G1ToBigIntArray(userPk), G2ToBigIntArray(proof31.G2ToAlpha), G2ToBigIntArray(proof31.G2ToBeta))
	receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
	fmt.Printf("PKtoSC Gas used: %d\n", receipt1.GasUsed)

	auth100 := utils.Transact(client, privatekey1, big.NewInt(0))
	intArray := rwdabe.MakeIntArry(proof31)
	tx2, _ := ctc.ProoftoSC(
		auth100,
		G1ToBigIntArray(key31Enc.Key),
		G2ToBigIntArray(key31Enc.KeyPrime),
		G1ToBigIntArray(key31Enc.EK2),
		G1ToBigIntArray(proof31.Key),
		G2ToBigIntArray(proof31.KeyPrime),
		G1ToBigIntArray(proof31.EK2P),
		intArray,
		gid,
		key31Enc.Attrib)
	receipt2, _ := bind.WaitMined(context.Background(), client, tx2)
	fmt.Printf("ProoftoSC Gas used: %d\n", receipt2.GasUsed)

	autht := utils.Transact(client, privatekey1, big.NewInt(0))
	tx3, err := ctc.Checkkey(autht) //checkkey on-chain
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Onchain Checkkey result:", tx3)
	receipt3, _ := bind.WaitMined(context.Background(), client, tx3)
	fmt.Printf("Checkkey Gas used: %d\n", receipt3.GasUsed)

	//judgeAttrs
	for _, acjudge := range acjudges {
		auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx1, _ := ctc.Validate(auth2, acjudge.Props, acjudge.ACS)
		receipt1, err := bind.WaitMined(context.Background(), client, tx1)
		res, err := ctc.Expects(&bind.CallOpts{}, "false")
		fmt.Printf("res: %v\n", res)
		if err != nil {
			log.Fatalf("Tx receipt failed: %v", err)
		}
		fmt.Printf("acjudge%s Gas used: %d\n", acjudge, receipt1.GasUsed)
	}

	fmt.Println("...........................................................Access...........................................................")

	key31 := auth3.GetKey(key31Enc, userSk)
	key32 := auth3.GetKey(key32Enc, userSk)

	// user tries to decrypt with different key combos
	ks1 := []*rwdabe.MAABEKey{key11, key21, key31, key41} // ok
	ks2 := []*rwdabe.MAABEKey{key12, key22, key32}        // ok
	ks5 := []*rwdabe.MAABEKey{key31, key32, key42}        // ok

	// try to decrypt all messages
	msg1, _ := maabe.ABEDecrypt(ct, ks1)

	msg2, _ := maabe.ABEDecrypt(ct, ks2)

	msg5, _ := maabe.ABEDecrypt(ct, ks5)

	fmt.Println("msg1", msg1)
	fmt.Println("msg2", msg2)
	fmt.Println("msg5", msg5)
	fmt.Println("Decrypt Result is:", msg1 == msg)

}
