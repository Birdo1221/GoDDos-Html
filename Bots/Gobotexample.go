package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type BotClient struct {
	serverAddr string
	conn       net.Conn
	running    bool
}

func NewBotClient(serverAddr string) *BotClient {
	return &BotClient{
		serverAddr: serverAddr,
		running:    false,
	}
}

func (b *BotClient) Connect() error {
	var err error
	b.conn, err = net.Dial("tcp", b.serverAddr)
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}

	b.running = true
	fmt.Printf("[+] Connected to %s\n", b.serverAddr)

	// Send initial handshake
	_, err = b.conn.Write([]byte("Bot connected\n"))
	if err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	go b.listenForCommands()

	return nil
}

func (b *BotClient) listenForCommands() {
	reader := bufio.NewReader(b.conn)
	for b.running {
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[-] Error reading command: %v\n", err)
			b.Disconnect()
			return
		}

		command := message[:len(message)-1] // Remove newline
		fmt.Printf("\n[+] Received command: %s\n", command)
		fmt.Println("[*] Processing command...")

		// Simulate processing
		time.Sleep(1 * time.Second)

		// Send response
		response := fmt.Sprintf("Executed: %s\n", command)
		_, err = b.conn.Write([]byte(response))
		if err != nil {
			log.Printf("[-] Error sending response: %v\n", err)
			b.Disconnect()
			return
		}
	}
}

func (b *BotClient) Disconnect() {
	if b.conn != nil {
		b.conn.Close()
	}
	b.running = false
	fmt.Println("[+] Disconnected from server")
}

func main() {
	fmt.Println(`
	____        _   
	|  _ \      | |  
	| |_) | ___ | |_ 
	|  _ < / _ \| __|
	| |_) | (_) | |_ 
	|____/ \___/ \__|
	Go Bot Client
	`)

	bot := NewBotClient("127.0.0.1:9080")
	err := bot.Connect()
	if err != nil {
		log.Fatalf("[-] Failed to connect: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	bot.Disconnect()
}
