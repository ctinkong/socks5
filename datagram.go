package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

type Datagram struct {
	memCreater MemAllocation
	// 保留字段
	Rsv []byte // 0x00 0x00
	// 该数据包的片段序号，如果值为X'00'则说明该数据包为独立数据包，如果为1~127的某个值，则说明为整个数据包的一个片段。
	Frag byte
	// 指定DST.ADDR的类型
	// IPV4: X'01'
	// 域名: X'03'
	// IPV6: X'04'
	ATyp byte
	// 该数据包渴望到达的目标地址
	DstAddr []byte
	// 该数据包渴望到达的目标端口
	DstPort []byte
	// 实际要传输的数据
	Data []byte
}

func (d *Datagram) free(ctx context.Context) {
	d.memCreater.Free(ctx, d.Rsv)
}

func (d *Datagram) toBytes(ctx context.Context, buf []byte) int {
	totalLen := 2 + 1 + 1 + len(d.DstAddr) + len(d.DstPort) + len(d.Data)
	if totalLen > len(buf) {
		return -1
	}
	idx := 0
	copy(buf, d.Rsv)
	idx += len(d.Rsv)
	buf[idx] = d.Frag
	idx++
	buf[idx] = d.ATyp
	idx++
	copy(buf[idx:], d.DstAddr)
	idx += len(d.DstAddr)
	copy(buf[idx:], d.DstPort)
	idx += len(d.DstPort)
	copy(buf[idx:], d.Data)
	idx += len(d.Data)
	return totalLen
}

func (d *Datagram) Address() string {
	var s string
	if d.ATyp == fqdnAddress {
		s = bytes.NewBuffer(d.DstAddr[1:]).String()
	} else {
		s = net.IP(d.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(d.DstPort)))
	return net.JoinHostPort(s, p)
}

/*
+-----+------+------+----------+----------+----------+
| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+-----+------+------+----------+----------+----------+
|  2  |  1   |  1   | Variable |    2     | Variable |
+-----+------+------+----------+----------+----------+
*/
func NewDatagramFromByte(ctx context.Context, memCreater MemAllocation, bs []byte) (*Datagram, error) {
	needLen := 4
	dataLen := len(bs)
	if dataLen <= needLen {
		return nil, fmt.Errorf("Datagram Illegal")
	}
	var frag = bs[2]
	if frag != 0x00 {
		// FIXME目前不支持分片
		return nil, fmt.Errorf("Datagram Not Support Slice Transmission")
	}
	var aTyp = bs[3]
	var dstAddr []byte
	var dstPort []byte
	// addr
	switch aTyp {
	case ipv4Address:
		// ipv4
		needLen += 4
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		dstAddr = bs[needLen-4 : needLen]
	case ipv6Address:
		// ipv6
		needLen += 16
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		dstAddr = bs[needLen-16 : needLen]
	case fqdnAddress:
		//域名
		needLen += 1
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		domainLen := int(bs[needLen-1])
		if domainLen == 0 {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		needLen += domainLen
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		dstAddr = bs[needLen-domainLen : needLen]
	default:
		return nil, fmt.Errorf("Datagram Illegal")
	}
	// port
	needLen += 2
	if dataLen < needLen {
		return nil, fmt.Errorf("Datagram Illegal")
	}
	dstPort = bs[needLen-2 : needLen]
	if dstPort[0] == 0 && dstPort[1] == 0 {
		return nil, fmt.Errorf("Datagram Illegal")
	}
	if len(bs[needLen:]) == 0 {
		return nil, fmt.Errorf("Datagram Has No Data")
	}
	buf := memCreater.Alloc(ctx, 2+len(dstAddr)+len(dstPort)+len(bs[needLen:]))
	bufIdx := 0

	datagram := new(Datagram)
	datagram.memCreater = memCreater
	datagram.Rsv = buf[bufIdx:2]
	copy(datagram.Rsv, bs[:2])
	bufIdx += 2
	datagram.Frag = frag
	datagram.ATyp = aTyp
	datagram.DstAddr = buf[bufIdx : len(dstAddr)+bufIdx]
	copy(datagram.DstAddr, dstAddr)
	bufIdx += len(dstAddr)
	datagram.DstPort = buf[bufIdx : len(dstPort)+bufIdx]
	copy(datagram.DstPort, dstPort)
	bufIdx += len(dstPort)
	datagram.Data = buf[bufIdx : len(bs[needLen:])+bufIdx]
	copy(datagram.Data, bs[needLen:])
	return datagram, nil
}

/*
+-----+------+------+----------+----------+----------+
| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+-----+------+------+----------+----------+----------+
|  2  |  1   |  1   | Variable |    2     | Variable |
+-----+------+------+----------+----------+----------+
*/
func NewDatagram(ctx context.Context, memCreater MemAllocation, aTyp byte, dstAddr, dstPort, data []byte) *Datagram {
	if aTyp == fqdnAddress {
		dstAddr = append([]byte{byte(len(dstAddr))}, dstAddr...)
	}
	buf := memCreater.Alloc(ctx, 2+len(dstAddr)+len(dstPort)+len(data))
	bufIdx := 0

	datagram := new(Datagram)
	datagram.memCreater = memCreater
	datagram.Rsv = buf[bufIdx:2]
	datagram.Rsv[0] = 0x00
	datagram.Rsv[1] = 0x00
	bufIdx += 2
	datagram.Frag = 0x00
	datagram.ATyp = aTyp
	datagram.DstAddr = buf[bufIdx : len(dstAddr)+bufIdx]
	copy(datagram.DstAddr, dstAddr)
	bufIdx += len(dstAddr)
	datagram.DstPort = buf[bufIdx : len(dstPort)+bufIdx]
	copy(datagram.DstPort, dstPort)
	bufIdx += len(dstPort)
	datagram.Data = buf[bufIdx : len(data)+bufIdx]
	copy(datagram.Data, data)
	return datagram
}
