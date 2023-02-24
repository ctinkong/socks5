package socks5

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// 测试使用
type BindCallBackFun func(bindAddr string)

var BindCallBack BindCallBackFun

func doBind(ctx context.Context, s *Server, conn conn, req *Request) error {
	// 随机绑定端口
	listenTcp, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		s.config.Logger.Printf("doBind Listen fail: %v\n", err)
		sendReply(conn, serverFailure, nil)
		return err
	}
	defer listenTcp.Close()
	s.config.Logger.Printf("doBind Listen %v\n", listenTcp.Addr().String())
	if BindCallBack != nil {
		BindCallBack(listenTcp.Addr().String())
	}

	// 获取绑定端口
	_, port, err := net.SplitHostPort(listenTcp.Addr().String())
	if err != nil {
		return fmt.Errorf("doBind Failed to SplitHostPort: %v", err)
	}
	bindPort, _ := strconv.Atoi(port)
	// 回复绑定地址
	bindAddr := AddrSpec{IP: s.config.BindIP, Port: bindPort}
	if err = sendReply(conn, successReply, &bindAddr); err != nil {
		return fmt.Errorf("doBind Failed to send reply: %v", err)
	}
	// 接受请求
	var tcpConn net.Conn
	for {
		tcpConn, err = listenTcp.Accept()
		if err != nil {
			s.config.Logger.Printf("doBind Accept fail: %v\n", err)
			sendReply(conn, serverFailure, nil)
			return err
		}
		//FIXME 是否限制IP?
		// remoteIp, _, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
		// // 只接受来自目标IP的连接
		// if remoteIp != req.DestAddr.IP.String() {
		// 	tcpConn.Close()
		// 	continue
		// }
		s.config.Logger.Printf("doBind accept one connection from %v\n", tcpConn.RemoteAddr().String())
		break
	}
	defer tcpConn.Close()

	remoteIp, port, err := net.SplitHostPort(tcpConn.RemoteAddr().String())
	if err != nil {
		s.config.Logger.Printf("doBind Failed to SplitHostPort accept tcp addr: %v\n", err)
		sendReply(conn, serverFailure, nil)
		return err
	}
	remotePort, _ := strconv.Atoi(port)
	// 回复连接地址
	acceptAddr := AddrSpec{IP: net.ParseIP(remoteIp), Port: remotePort}
	if err = sendReply(conn, successReply, &acceptAddr); err != nil {
		return fmt.Errorf("doBind Failed to send reply: %v", err)
	}

	errCh := make(chan error, 2)
	go proxy(tcpConn, req.bufConn, errCh)
	go proxy(conn, tcpConn, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}
