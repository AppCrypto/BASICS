package main

import (
	"basics/compile/contract"
	"basics/utils"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math/big"
)

type ACJudge struct {
	Props []string `json:"props"`
	ACS   string   `json:"acs"`
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

}
