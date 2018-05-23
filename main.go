package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"strconv"
	"strings"
	"time"

	"encoding/json"
	"net/http"
	"os"
	"io"
	"sync"
	"log"
	"github.com/joho/godotenv"
)

const difficulty = 1

var BlockChain []Block

var mutex = &sync.Mutex{}

//Message 通过post实现的数据发送的类型
type Message struct {
	BMP  int
}

type Block struct {

	//区块链中数据记录的位置
	Index     int
	Timestamp string
	//每分钟的跳动的次数，是你的脉率
	Bmp        int
	Hash       string
	PreHash    string
	Difficulty int
	Nonce      string
}

func main() {

	//允许我们从根目录的文件.env读取相应的变量
	err:= godotenv.Load()

	if err != nil {
		log.Fatal(err)
	}

	go func() {

		//创建初始区块
		t:=time.Now()
		genesisBlock := Block{}
		genesisBlock = Block{0,t.String(),0,calculateHash(genesisBlock),"",difficulty,""}
		spew.Dump(genesisBlock)
		mutex.Lock()
		BlockChain = append(BlockChain,genesisBlock)
		mutex.Unlock()
	}()

	//启动web服务
	log.Fatal(run())




}

//生成区块
func generateBlock(oldBlock Block, BMP int) Block {

	var newBlock Block
	t := time.Now()
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Bmp = BMP
	newBlock.PreHash = oldBlock.Hash
	newBlock.Difficulty = difficulty

	for i := 0; ; i++ {

		hex := fmt.Sprintf("%x", i)
		newBlock.Nonce = hex

		if !isHashValid(calculateHash(newBlock), difficulty) {
			fmt.Println(calculateHash(newBlock), "do more work")
			time.Sleep(time.Second)
			continue
		} else {
			fmt.Println(calculateHash(newBlock), "work done")
			newBlock.Hash = calculateHash(newBlock)
			break
		}

	}

	return newBlock

}

//验证哈希

func isHashValid(hash string, difficulty int) bool {

	//难度为几就是几个0的字符串
	prefix := strings.Repeat("0", difficulty)

	//判断hash字符串是否有前缀有prefix
	return strings.HasPrefix(hash, prefix)

}

//生成哈希

func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + strconv.Itoa(block.Bmp) + block.PreHash + block.Nonce

	sh := sha256.New()

	sh.Write([]byte(record))

	hash := sh.Sum(nil)
	return hex.EncodeToString(hash)

}

//验证区块

func isBlockValid(oldBlock Block, newBlock Block) bool {

	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if newBlock.PreHash != oldBlock.Hash {
		return false
	}
	if calculateHash(newBlock) != newBlock.Hash {
		return false

	}

	return true
}

//web 服务器
func run() error {
	mux := makeMuxRouter()
	httpAddr := os.Getenv("ADDR")
	log.Println("Listening on",os.Getenv("ADDR"))
	s:= &http.Server{

		Addr:":" + httpAddr,
		Handler:mux,
		ReadTimeout:10*time.Second,
		WriteTimeout:time.Second *10,
		MaxHeaderBytes:1<<20,
	}
	if err := s.ListenAndServe();err!=nil {
		return err
	}

	return nil
}

//主要定义路由
func makeMuxRouter() http.Handler {

	muxRouter := mux.NewRouter()
	//当接受到get请求是，调用handleGetBlockchain
	muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlockchain).Methods("POST")

	return muxRouter

}

//获取所有的区块的列表信息
func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	   bytes,err := json.MarshalIndent(BlockChain, "", "   ")
	if err != nil {
		http.Error(w,err.Error(),http.StatusInternalServerError)
		return
	}else {

		io.WriteString(w,string(bytes))

	}

}

//主要是生成新的区块
func handleWriteBlockchain(w http.ResponseWriter,r *http.Request) {

	w.Header().Set("Content-Type","application/json")
	var m Message

	decoder :=json.NewDecoder(r.Body)

	if err := decoder.Decode(&m);err != nil {
		respondWithJson(w,r,http.StatusInternalServerError,r.Body)
		return

	}
	defer r.Body.Close()
	//当创建区块的时候保证原子性，上锁
	mutex.Lock()
	newBlock:= generateBlock(BlockChain[len(BlockChain) -1],m.BMP)
	mutex.Unlock()

	if isBlockValid(newBlock,BlockChain[len(BlockChain) - 1]) {
		BlockChain = append(BlockChain,newBlock)
		spew.Dump(BlockChain)
	}
	respondWithJson(w,r,http.StatusCreated,newBlock)

}

func respondWithJson(w http.ResponseWriter,r *http.Request,code int,payload interface{})  {

	w.Header().Set("Content-Type","application/json")
	response,err := json.MarshalIndent(payload,"","  ")
	if err != nil{
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Http 500:Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)

}