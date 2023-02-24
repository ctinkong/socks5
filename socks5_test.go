package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	ssock "github.com/txthinking/socks5"
	ssock2 "github.com/wzshiming/socks5"
)

func TestSOCKS5_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:12000")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12365"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	conn, err := net.Dial("tcp", "127.0.0.1:12365")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Connect, auth and connec to local
	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	// Send a ping
	req.Write([]byte("ping"))

	// Send all the bytes
	conn.Write(req.Bytes())

	// Verify response
	expected := []byte{
		socks5Version, UserPassAuth,
		1, authSuccess,
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ignore the port
	out[12] = 0
	out[13] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}
}

func TestSOCKS5_Associate(t *testing.T) {
	// Create a udp listener
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8888")
	l, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		defer l.Close()
		var buf [1024]byte
		for {
			n, from, err := l.ReadFromUDP(buf[:])
			if err != nil {
				t.Fatalf("err: %v", err)
				break
			}
			if i := bytes.Index(buf[:n], []byte("ping")); i == -1 {
				t.Fatalf("bad: %v", buf)
			} else {
				idx, _ := strconv.Atoi(string(buf[4:n]))
				msg := fmt.Sprintf("pong%v", idx)
				fmt.Printf("@@@ response udp read %v, echo %v @@@\n", string(buf[:n]), msg)
				l.WriteToUDP([]byte(msg), from)
			}
		}
	}()

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		BindIP:      net.ParseIP("127.0.0.1"),
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12366"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// 10 task
	n := 10
	var wg = sync.WaitGroup{}
	for ; n > 0; n-- {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			s5, err := ssock.NewClient("127.0.0.1:12366", "foo", "bar", 0, 0)
			if err != nil {
				t.Fatalf("NewClient err: %v", err)
				return
			}
			conn, err := s5.Dial("udp", "local.cloudpc.cn:8888")
			if err != nil {
				t.Fatalf("NewClient err: %v", err)
				return
			}
			defer conn.Close()

			var buf [1024]byte
			msg := fmt.Sprintf("ping%v", i)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				t.Fatalf("conn.Write err: %v", err)
				return
			}
			l, err := conn.Read(buf[:])
			fmt.Printf("### response len %v: %v ###\n", l, string(buf[:l]))
		}(n)
	}
	wg.Wait()
}

func TestSocks5_Bind(t *testing.T) {
	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		BindIP:      net.ParseIP("127.0.0.1"),
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
		return
	}
	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12367"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// 获取 bind cmd 绑定的端口，只在测试中使用
	var socks5ServerBindPort int
	cb := func(bindAddr string) {
		_, port, err := net.SplitHostPort(bindAddr)
		if err == nil {
			fmt.Printf("@@@@@ socks5 server bind port %v\n", port)
			socks5ServerBindPort, _ = strconv.Atoi(port)
		}
	}
	BindCallBack = cb

	time.Sleep(10 * time.Millisecond)

	// bind client
	dial, err := ssock2.NewDialer("socks5://127.0.0.1:12367")
	if err != nil {
		t.Fatal(err)
		return
	}
	dial.Username = "foo"
	dial.Password = "bar"
	listener, err := dial.Listen(context.Background(), "tcp", ":12000")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer listener.Close()

	var wg = sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// accept from socks5 server
		client, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
			return
		}
		defer client.Close()

		fmt.Printf("bind recv one from %v\n", client.LocalAddr().String())

		var bs [4096]byte
		n, err := client.Read(bs[:])
		if err == nil {
			fmt.Printf("=================\nbind server recv:\n%v\n", string(bs[:n]))
			client.Write([]byte("HTTP/1.1 200 OK\r\nServer: sock5\r\nContent-Length: 10\r\n\r\n1234567890"))
		}
	}()
	defer wg.Wait()

	// 等待端口绑定成功
	for socks5ServerBindPort == 0 {
		time.Sleep(time.Millisecond)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%v", socks5ServerBindPort))
	if err != nil {
		fmt.Printf("net.Dial fail %v\n", err)
		return
	}
	defer conn.Close()
	fmt.Printf("connect port %v success\n", socks5ServerBindPort)

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	if err != nil {
		fmt.Printf("write data fail %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var bs [4096]byte
	n, err := conn.Read(bs[:])
	if err != nil {
		fmt.Printf("read data fail %v\n", err)
		return
	}
	fmt.Printf("=================\nhttp rsp:\n%v\n\n", string(bs[:n]))
}
