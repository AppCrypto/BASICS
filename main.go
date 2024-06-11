package main

import (
	"basics/compile/contract"
	"basics/crypto/rwdabe"
	"basics/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"strconv"
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
	acjudges := make([]*ACJudge, 1)
	acjudges[0] = generateACPStr(5)
	fmt.Println(acjudges[0])

	contract_name := "Basics"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

	address, _ := utils.Deploy(client, contract_name, deployTX)

	ctc, err := contract.NewContract(common.HexToAddress(address.Hex()), client)

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

	maabe := rwdabe.NewMAABE()

	// create three authorities, each with two attributes
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	attribs4 := []string{"auth4:at1", "auth4:at2"}
	auth1, _ := maabe.NewMAABEAuth("auth1")
	auth2, _ := maabe.NewMAABEAuth("auth2")
	auth3, _ := maabe.NewMAABEAuth("auth3")
	auth4, _ := maabe.NewMAABEAuth("auth4")
	// create a msp struct out of the boolean formula
	//msp, _ := lib.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	msp, _ := lib.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth4:at1", false)
	// define the set of all public keys we use
	pks := []*rwdabe.MAABEPubKey{auth1.Pk, auth2.Pk, auth3.Pk, auth4.Pk}

	// choose a message
	msg := "Attack at dawn!"

	// encrypt the message with the decryption policy in msp
	ct, _ := maabe.ABEEncrypt(msg, msp, pks)

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user
	key11, err := auth1.ABEKeyGen(gid, attribs1[0])
	//keys1[1]
	key12, _ := auth1.ABEKeyGen(gid, attribs1[1])
	// authority 2 issues keys to user
	key21, _ := auth2.ABEKeyGen(gid, attribs2[0])
	key22, _ := auth2.ABEKeyGen(gid, attribs2[1])
	key41, _ := auth4.ABEKeyGen(gid, attribs4[0])
	key42, _ := auth4.ABEKeyGen(gid, attribs4[1])

	// authority 3 issues keys to user
	//key31, err := auth3.ABEKeyGen(gid, attribs3[0])
	userSk := rwdabe.RandomInt()
	userPk := new(bn128.G1).ScalarMult(auth3.Maabe.G1, userSk)
	key31Enc, _ := auth3.ABEKeyGen(gid, attribs3[0], userPk)
	proof, _ := auth3.KeyGenPrimeAndGenProofs(key31Enc, userPk)
	res, err := maabe.CheckKey(userPk, key31Enc, proof)
	if !res {
		fmt.Println("Failed to checkKey attribute keys: %v\n", err)
	}
	key31 := auth3.GetKey(key31Enc, userSk)
	//fmt.Println("GetKey", key31Enc.Key)
	key32, err := auth3.ABEKeyGen(gid, attribs3[1])
	// user tries to decrypt with different key combos
	ks1 := []*rwdabe.MAABEKey{key11, key21, key31, key41} // ok
	ks2 := []*rwdabe.MAABEKey{key12, key22, key32}        // ok
	ks5 := []*rwdabe.MAABEKey{key31, key32, key42}        // ok

	// try to decrypt all messages
	msg1, _ := maabe.ABEDecrypt(ct, ks1)

	msg2, _ := maabe.ABEDecrypt(ct, ks2)

	msg5, err := maabe.ABEDecrypt(ct, ks5)

	fmt.Println("msg1", msg1)
	fmt.Println("msg2", msg2)
	fmt.Println("msg5", msg5)

}
