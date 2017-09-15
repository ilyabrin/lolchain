package main

import "fmt"
import "time"
import "strconv"
import "bytes"
import "crypto/sha256"

type Block struct {
	Data          []byte
	Hash          []byte
	PrevBlockHash []byte
	Timestamp     int64
}

type Blockchain struct {
	blocks []*Block
}

func (b *Block) SetHash() {
	ts := []byte(strconv.FormatInt(b.Timestamp, 10))
	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, ts}, []byte{})
	hash := sha256.Sum256(headers)

	b.Hash = hash[:]
}

func NewBlock(data string, prevBlockHash []byte) *Block {
	block := &Block{
		[]byte(data),
		[]byte{},
		prevBlockHash,
		time.Now().Unix(),
	}
	block.SetHash()

	return block
}

func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(data, prevBlock.Hash)
	bc.blocks = append(bc.blocks, newBlock)
}

func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}

func main() {
	blockchain := NewBlockchain()

	blockchain.AddBlock("Send 1 coin to Kate")
	blockchain.AddBlock("Sent 4 coint to Kate")

	for _, block := range blockchain.blocks {
		fmt.Printf("Previous hash: %x \n", block.PrevBlockHash)
		fmt.Printf("Data: %s \n", block.Data)
		fmt.Printf("Hash: %x \n", block.Hash)
		fmt.Println()
	}
}
