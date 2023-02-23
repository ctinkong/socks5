package socks5

import (
	"net"
)

var udpServer UdpServer

func UdpInstance() *UdpServer {
	return &udpServer
}

type UdpServer struct {
	ls *net.UDPConn
}

func newUdpServer() *UdpServer {
	return new(UdpServer)
}

// func (us *UdpServer) ListenAndServe(network, addr string) error {
// 	udpAddr, err := net.ResolveUDPAddr(network, addr)
// 	if err != nil {
// 		return err
// 	}
// 	us.ls, err = net.ListenUDP(network, udpAddr)
// 	if err != nil {
// 		return err
// 	}
// 	return us.Serve()
// }

func (us *UdpServer) Listen(network, addr string) error {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return err
	}
	us.ls, err = net.ListenUDP(network, udpAddr)
	return err
}

// func (us *UdpServer) Serve() error {
// 	bs := make([]byte, 65536)
// 	for {
// 		n, addr, err := us.ls.ReadFromUDP(bs)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

func (us *UdpServer) ReadFromUdp(bs []byte) (int, *net.UDPAddr, error) {
	return us.ls.ReadFromUDP(bs)
}

func (us *UdpServer) WriteToUDP(bs []byte, addr *net.UDPAddr) (int, error) {
	return us.ls.WriteToUDP(bs, addr)
}

func (us *UdpServer) LocalAddr() net.Addr {
	return us.ls.LocalAddr()
}

func (us *UdpServer) Close() error {
	return us.ls.Close()
}
