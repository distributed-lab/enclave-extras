package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/vsock"
)

func dialVsockWithRetries(cid, port uint32, attempts int, delay time.Duration) (net.Conn, error) {
	var c net.Conn
	var err error

	for i := 1; i <= attempts; i++ {
		c, err = vsock.Dial(cid, port, nil)
		if err == nil {
			return c, nil
		}
		log.Printf("Dial vsock attempt %d/%d failed: %v", i, attempts, err)
		time.Sleep(delay)
	}

	return nil, fmt.Errorf("failed to connect to vsock(%d, %d) after %d attempts: %w", cid, port, attempts, err)
}

func handleClient(clientConn net.Conn, cid, port uint32, attempts int, delay time.Duration) {
	defer clientConn.Close()

	vsockConn, err := dialVsockWithRetries(cid, port, attempts, delay)
	if err != nil {
		log.Printf("Sidecar: could not connect to vsock after retries, closing client: %v", err)
		return
	}
	defer vsockConn.Close()

	wg := new(sync.WaitGroup)
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(vsockConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, vsockConn)
	}()

	wg.Wait()
}

func main() {
	var (
		parentCID uint
		vsockPort uint
		localAddr string
		attempts  int
		delay     time.Duration
	)

	flag.UintVar(&parentCID, "parentCID", 3, "the parent's context ID to connect")
	flag.UintVar(&vsockPort, "vsockPort", 8000, "the vsock port to connect")
	flag.StringVar(&localAddr, "localAddr", "127.0.0.1:443", "the local address to listen on")
	flag.IntVar(&attempts, "attempts", 100, "the number of attempts to connect")
	flag.DurationVar(&delay, "delay", 10*time.Second, "the duration to wait between attempts")

	flag.Parse()

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", localAddr, err)
	}
	log.Printf("VSOCK Proxy listening on %s, forwarding to vsock(%d, %d)", localAddr, parentCID, vsockPort)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleClient(clientConn, uint32(parentCID), uint32(vsockPort), attempts, delay)
	}
}
