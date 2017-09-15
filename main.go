package main

import "fmt"
import "time"
import "bytes"
import "crypto/sha256"
import "encoding/binary"
import "encoding/gob"
import "math"
import "math/big"
import "strconv"
import "flag"
import "os"

import "github.com/boltdb/bolt"

const targetBits = 24
const maxNonce = math.MaxInt64
const blockchain = "blockchain.bolt"
const blocksBucket = "blocks"

type CLI struct {
	blockchain *Blockchain
}

type Block struct {
	Data          []byte
	Hash          []byte
	PrevBlockHash []byte
	Timestamp     int64
	Nonce         int
}

type Blockchain struct {
	tip []byte
	db  *bolt.DB
}

type BlockchainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func (cli *CLI) Run() {
	cli.validateArgs()

	addBlock_command := flag.NewFlagSet("addblock", flag.ExitOnError)
	allChain_command := flag.NewFlagSet("allchain", flag.ExitOnError)

	addBlockData := addBlock_command.String("data", "", "Block data")

	switch os.Args[1] {
	case "addblock":
		err := addBlock_command.Parse(os.Args[2:])
		if err != nil {
			// log.Panic(err)
		}

	case "allchain":
		err := allChain_command.Parse(os.Args[2:])
		if err != nil {
			// log.Panic(err)
		}

	default:
		cli.printUsage()
		os.Exit(1)
	}

	if addBlock_command.Parsed() {
		if *addBlockData == "" {
			addBlock_command.Usage()
			os.Exit(1)
		}
		cli.addBlock(*addBlockData)
	}

	if allChain_command.Parsed() {
		cli.allChain()
	}
}

func (cli *CLI) validateArgs() {
	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}
}

func (cli *CLI) printUsage() {
	fmt.Println("Usage:")
	fmt.Println(" addblock -data BLOCK_DATA - add a block to the blockchain")
	fmt.Println(" allchain - print all the blockchain blocks")
}

func (cli *CLI) addBlock(data string) {
	cli.blockchain.AddBlock(data)
	fmt.Println("Successfully added!")
}

func (cli *CLI) allChain() {
	iterator := cli.blockchain.Iterator()

	for {
		block := iterator.Next()

		fmt.Printf("Previous hash: %x \n", block.PrevBlockHash)
		fmt.Printf("Data: %s \n", block.Data)
		fmt.Printf("Hash: %x \n", block.Hash)

		pow := NewProofOfWork(block)

		fmt.Printf("Proof-Of-Work: %s \n", strconv.FormatBool(pow.Validate()))

		fmt.Println()

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}
}

func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

func (b *Block) SerializeBlock() []byte {
	var data bytes.Buffer
	encoder := gob.NewEncoder(&data)

	err := encoder.Encode(b)
	if err != nil {
		// log.Panic(err)
		fmt.Println("DeserializeBlock error")
	}

	return data.Bytes()
}

func DeserializeBlock(data []byte) *Block {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&block)

	if err != nil {
		// log.Panic(err)
		println("Deserializing error")
	}

	return &block
}

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

	var lastHash []byte

	err := bc.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blocksBucket))
		lastHash = bucket.Get([]byte("l"))

		return nil
	})

	if err != nil {
		// log.Panic(err)
	}

	newBlock := NewBlock(data, lastHash)

	err = bc.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blocksBucket))

		err := bucket.Put(newBlock.Hash, newBlock.SerializeBlock())
		if err != nil {
			// log.Panic(err)
		}

		err = bucket.Put([]byte("l"), newBlock.Hash)
		if err != nil {
			// log.Panic(err)
		}

		bc.tip = newBlock.Hash

		return nil
	})
}

func (bc *Blockchain) Iterator() *BlockchainIterator {
	iterator := &BlockchainIterator{bc.tip, bc.db}
	return iterator
}

func (iterator *BlockchainIterator) Next() *Block {
	var block *Block

	err := iterator.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blocksBucket))
		encodedBlock := bucket.Get(iterator.currentHash)
		block = DeserializeBlock(encodedBlock)

		return nil
	})

	if err != nil {
		// log.Panic(err)
	}

	iterator.currentHash = block.PrevBlockHash

	return block
}

func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

func NewBlockchain() *Blockchain {

	var tip []byte

	db, err := bolt.Open(blockchain, 0600, nil)

	if err != nil {
		// log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blocksBucket))

		if bucket == nil {
			fmt.Println("Blockchain not found. Creating ...")
			genesis := NewGenesisBlock()

			bucket, err := tx.CreateBucket([]byte(blocksBucket))
			if err != nil {
				// log.Panic(err)
			}

			err = bucket.Put(genesis.Hash, genesis.SerializeBlock())
			if err != nil {
				// log.Panic(err)
			}

			err = bucket.Put([]byte("l"), genesis.Hash)
			if err != nil {
				// log.Panic(err)
			}

			tip = genesis.Hash
		} else {
			tip = bucket.Get([]byte("l"))
		}

		return nil
	})

	if err != nil {
		// log.Panic(err)
	}

	bc := Blockchain{tip, db}

	return &bc
}

func IntToHex(n int64) []byte {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, n)

	if err != nil {
		// log.Panic(err)
	}

	return buffer.Bytes()
}

func main() {
	blockchain := NewBlockchain()
	defer blockchain.db.Close()

	cli := CLI{blockchain}
	cli.Run()

}
