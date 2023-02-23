package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	ssock "github.com/txthinking/socks5"
)

func TestSOCKS5_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
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
	// Create a local listener
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
	n := 10
	for ; n > 0; n-- {
		go func(i int) {
			s5, err := ssock.NewClient("127.0.0.1:12366", "foo", "bar", 0, 0)
			if err != nil {
				t.Fatalf("NewClient err: %v", err)
			}
			conn, err := s5.Dial("udp", "local.cloudpc.cn:8888")
			if err != nil {
				t.Fatalf("NewClient err: %v", err)
			}
			var buf [1024]byte
			msg := fmt.Sprintf("ping%v", i)
			for {
				_, err := conn.Write([]byte(msg))
				if err != nil {
					t.Fatalf("conn.Write err: %v", err)
					break
				}
				l, err := conn.Read(buf[:])
				fmt.Printf("### response len %v: %v ###\n", l, string(buf[:l]))
				time.Sleep(time.Second)
			}
			conn.Close()
			s5.Close()
		}(n)
	}
	select {}
}
