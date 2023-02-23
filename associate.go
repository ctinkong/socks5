/*
auth: https://github.com/ctinkong
*/
package socks5

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"time"
)

// 记录来自客户端连接的信息
type UdpPeer struct {
	updateTime int64       // 最后一次处理时间
	udpServer  *UdpServer  // 新创建的服务端udp 可能为空
	from       net.UDPAddr // 来自客户端地址
	req        *Request    // 请求信息
	dst        net.Conn    // 目标连接
	atyp       byte        // 目标地址类型
	dstAddr    []byte      // 目标地址
	dstPort    []byte      // 目标端口
}

type UdpAssociate struct {
	m map[string]*UdpPeer
}

func (ua *UdpAssociate) Set(key string, u *UdpPeer) {
	ua.m[key] = u
}

func (ua *UdpAssociate) Get(key string) (*UdpPeer, bool) {
	k, v := ua.m[key]
	return k, v
}

func (ua *UdpAssociate) Del(key string) {
	delete(ua.m, key)
}

func (ua *UdpAssociate) CloseAll() {
	for _, v := range ua.m {
		v.dst.Close()
	}
}

func NewUdpAssociate() *UdpAssociate {
	return &UdpAssociate{
		m: make(map[string]*UdpPeer),
	}
}

func doAssociate(ctx context.Context, s *Server, conn conn, req *Request) error {
	//FIXME tcp 与 udp 对必须要做关联，当tcp连接断开时，必须释放udp
	// 由于客户端请求udp中转时，DST.ADDR与DST.PORT可能是局域网地址（NAT之后）或者是 0
	// 或者是多个连接同时连接到相同的 目标地址
	// 导致服务端无法做到唯一匹配。一律 服务端新绑定端口与之对应：
	// 后续是否可以采用一下策略？
	// 1、如果 DST.ADDR 或者 DST.PORT 为零值，则；
	// 2、如果 DST.ADDR 为局域网地址，则服务端新绑定端口与之对应；
	// 3、如果 DST.ADDR 公网地址，且目标地址没有连接过，则复用服务器端口，否则务端新绑定端口与之对应；
	bindPort := 0
	udpServer := newUdpServer()
	// 绑定随机端口
	err := udpServer.Listen("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("doAssociate Failed to bind udp server: %v", err)
	}
	_, port, err := net.SplitHostPort(udpServer.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("1 doAssociate Failed to SplitHostPort: %v", err)
	}
	bindPort, _ = strconv.Atoi(port)
	defer udpServer.Close()

	// 创建内存分配器
	var memCreater MemAllocation
	if s.config.Mem != nil {
		memCreater = s.config.Mem.Create(ctx)
	} else {
		memCreater = new(Mem)
	}
	go func() {
		// 保持sock5连接请求
		io.Copy(ioutil.Discard, conn.(*net.TCPConn))
	}()

	// Send success
	bind := AddrSpec{IP: s.config.BindIP, Port: bindPort}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("1 Failed to send reply: %v", err)
	}
	return readFromSrc(ctx, s, req, udpServer, memCreater)
}

// 处理来自客户端的数据
func readFromSrc(ctx context.Context, s *Server, req *Request, udpServer *UdpServer, memCreater MemAllocation) error {
	// 创建缓存新连接的结构体
	peers := NewUdpAssociate()
	// udp数据包不能超过65536
	bs := make([]byte, 65536)
	var n int
	var from *net.UDPAddr
	var err error
	var datagram *Datagram
	for {
		// 读取来自客户端数据
		n, from, err = udpServer.ReadFromUdp(bs)
		if err != nil {
			break
		}
		// 解析数据
		datagram, err = NewDatagramFromByte(ctx, memCreater, bs[:n])
		if err != nil {
			break
		}
		// s.config.Logger.Printf("readFromSrc %v data len %v\n", from.String(), n)
		// 处理数据
		handleDatagram(ctx, s, req, peers, udpServer, memCreater, from, datagram)
		// s.config.Logger.Printf("handleDatagram finish.\n")
		// 释放内存
		datagram.free(ctx)
		datagram = nil
	}
	fmt.Printf("readFromSrc fail: %v\n", err)
	// sock5连接结束 释放所有请求
	peers.CloseAll()
	if datagram != nil {
		datagram.free(ctx)
	}
	return err
}

// 处理来自客户端的数据
func handleDatagram(ctx context.Context, s *Server, req *Request, peers *UdpAssociate,
	udpServer *UdpServer, memCreater MemAllocation,
	from *net.UDPAddr, datagram *Datagram) error {
	// 计算key
	key := from.String() + "-" + datagram.Address()

	// s.config.Logger.Printf("handleDatagram key %v\n", key)

	udpPeer, ok := peers.Get(key)
	if !ok {
		// 新连接
		// 尝试连接
		dial := s.config.Dial
		if dial == nil {
			dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
				return net.Dial(net_, addr)
			}
		}
		dst, err := dial(ctx, "udp", datagram.Address())
		if err != nil {
			return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
		}
		s.config.Logger.Printf("handleDatagram dail %v success.\n", datagram.Address())

		// 创建新的连接
		udpPeer = new(UdpPeer)
		udpPeer.updateTime = time.Now().Unix()
		udpPeer.udpServer = udpServer
		udpPeer.from = *from
		udpPeer.req = req
		udpPeer.dst = dst
		udpPeer.atyp = datagram.ATyp
		//Notice 不能直接引用 datagram 的所有引用类型数据
		udpPeer.dstAddr = make([]byte, len(datagram.DstAddr))
		copy(udpPeer.dstAddr, datagram.DstAddr)
		//Notice 不能直接引用 datagram 的所有引用类型数据
		udpPeer.dstPort = make([]byte, len(datagram.DstPort))
		copy(udpPeer.dstPort, datagram.DstPort)

		peers.Set(key, udpPeer)
		go readFromDst(ctx, s, udpPeer, memCreater)
	}
	// s.config.Logger.Printf("handleDatagram write to %v %v.\n", udpPeer.dst.RemoteAddr().String(), string(datagram.Data))
	_, err := udpPeer.dst.Write(datagram.Data)
	if err != nil {
		// 我想一般不会走到这里
		fmt.Printf("udpPeer.dst.Write fail: %v\n", err)
		udpPeer.dst.Close()
		peers.Del(key)
	} else {
		// 更新时间
		udpPeer.updateTime = time.Now().Unix()
	}
	return nil
}

// 处理来自目标地址的数据
func readFromDst(ctx context.Context, s *Server, udpPeer *UdpPeer, memCreater MemAllocation) error {
	bs := make([]byte, 65536)
	var n int
	var err error
	var datagram *Datagram
	for {
		n, err = udpPeer.dst.Read(bs)
		if err != nil {
			break
		}
		// s.config.Logger.Printf("readFromDst from dst data len %v.\n", n)
		datagram = NewDatagram(ctx, memCreater, udpPeer.atyp, udpPeer.dstAddr, udpPeer.dstPort, bs[:n])
		if datagram == nil {
			err = fmt.Errorf("readFromDst NewDatagram fail")
			break
		}
		n = datagram.toBytes(ctx, bs)
		if n <= 0 {
			err = fmt.Errorf("readFromDst NewDatagram packet more than 65536")
			break
		}
		_, err = udpPeer.udpServer.WriteToUDP(bs[:n], &udpPeer.from)
		if err != nil {
			break
		}
		// 更新时间
		udpPeer.updateTime = time.Now().Unix()
		// 释放内存
		datagram.free(ctx)
		datagram = nil
	}
	if datagram != nil {
		datagram.free(ctx)
	}
	return err
}
