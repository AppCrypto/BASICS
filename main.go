package main

import (
	"basics/compile/contract"
	"basics/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	bn128 "github.com/fentec-project/bn256"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
)

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

func main() {

	data := `[
		{"props": ["Alice", "Carl"], "acs": "Carl AND Alice"},
		{"props": ["Alice", "Carl","Tom"], "acs": "Carl AND Alice AND Tom"},
		{"props": ["Alice", "Bob", "Carl","Tom"], "acs": "Carl AND (Alice AND (Tom AND Bob))"},
		{"props": ["Alice", "Bob", "Carl","Tom","Eve"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve"},
		{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav"},
		{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB"},
		{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC"},
		{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC","AD"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC AND AD"},
		{"props": ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC","AD","AE"], "acs": "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC AND AD AND AE"},
		{"props": ["Alice"], "acs": "Alice OR Carl"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR Tom"},
		{"props": ["Alice"], "acs": "Carl OR (Alice OR (Tom OR Bob))"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD"},
		{"props": ["Alice"], "acs": "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD OR AE"}
	]`
	var acjudges []ACJudge
	// 解码 JSON 数据
	err := json.Unmarshal([]byte(data), &acjudges)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}
	//fmt.Println("Decoded JSON data:")

	contract_name := "Contract"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	auth1 := utils.Transact(client, privatekey1, big.NewInt(0))

	address, _ := utils.Deploy(client, contract_name, auth1)

	contract, err := contract.NewContract(common.HexToAddress(address.Hex()), client)

	for _, acjudge := range acjudges {
		//fmt.Printf("Props: %d, ACS: %s\n", acjudge.Props, acjudge.ACS)
		auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx1, _ := contract.Validate(auth2, acjudge.Props, acjudge.ACS)
		receipt1, err := bind.WaitMined(context.Background(), client, tx1)
		if err != nil {
			log.Fatalf("Tx receipt failed: %v", err)
		}
		fmt.Printf("acjudge%s Gas used: %d\n", acjudge, receipt1.GasUsed)

	}
	//curveOrder := bn128.Order
}
