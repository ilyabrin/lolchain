package main

import "fmt"
import "time"
import "bytes"
import "crypto/sha256"
import "encoding/binary"
import "math"
import "math/big"
import "strconv"

const targetBits = 24
const maxNonce = math.MaxInt64

type Block struct {
	Data          []byte
	Hash          []byte
	PrevBlockHash []byte
	Timestamp     int64
	Nonce         int
}

type Blockchain struct {
	blocks []*Block
}

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

// block := &Block{
// 	[]byte(data),
// 	[]byte{},
// 	prevBlockHash,
// 	time.Now().Unix(),
// 	0,
// }

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.Data,
			IntToHex(int64(targetBits)),
			pow.block.PrevBlockHash,
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)

	return data
}

func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte

	nonce := 0

	fmt.Printf("Mining the block containing \"%s\" \n", pow.block.Data)

	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)

		fmt.Printf("\r %x", hash)

		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	println("\n\n\n")

	return nonce, hash[:]
}

func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}

func NewBlock(data string, prevBlockHash []byte) *Block {
	block := &Block{
		[]byte(data),
		[]byte{},
		prevBlockHash,
		time.Now().Unix(),
		0,
	}

	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce

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

func IntToHex(n int64) []byte {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, n)

	if err != nil {
		println(err)
	}

	return buffer.Bytes()
}

func main() {
	blockchain := NewBlockchain()

	blockchain.AddBlock("Send 1 coin to Kate")
	blockchain.AddBlock("Send 4 coins to Kate")

	for _, block := range blockchain.blocks {
		fmt.Printf("Previous hash: %x \n", block.PrevBlockHash)
		fmt.Printf("Data: %s \n", block.Data)
		fmt.Printf("Hash: %x \n", block.Hash)
		pow := NewProofOfWork(block)
		fmt.Printf("Proof-Of-Work %s \n", strconv.FormatBool(pow.Validate()))
		fmt.Println()
	}
}
