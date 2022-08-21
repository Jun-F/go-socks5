package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

type ClientRequestMessage struct {
	Version     byte
	CMD         Command
	RSV         byte
	AddressType AddressType
	ADDR        string
	PORT        uint16
}

type Command byte

const (
	CommandConnect Command = 0x01
	CommandBind    Command = 0x02
	CommandUDP     Command = 0x03
)

type AddressType byte

const (
	AddressTypeIPV4   AddressType = 0x01
	AddressTypeDomain AddressType = 0x03
	AddressTypeIPV6   AddressType = 0x04
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	//读取前四位
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	version, command, reserved, addressType := buf[0], Command(buf[1]), buf[2], AddressType(buf[3])
	if version != Socks5Version {
		return nil, ErrVersionNotSupported
	}
	if command != CommandConnect && command != CommandBind && command != CommandUDP {
		return nil, ErrCommandNotSupported
	}
	if reserved != Socks5Reserved {
		return nil, ErrReservedNotSupported
	}
	if addressType != AddressTypeIPV4 && addressType != AddressTypeDomain && addressType != AddressTypeIPV6 {
		return nil, ErrAddressTypeNotSupported
	}

	clientRequestMessage := &ClientRequestMessage{
		Version:     version,
		CMD:         command,
		RSV:         reserved,
		AddressType: addressType,
	}

	//读取地址
	switch addressType {
	case AddressTypeIPV4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		clientRequestMessage.ADDR = net.IP(buf).String()
	case AddressTypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		length := buf[0]
		if length > net.IPv4len {
			buf = make([]byte, length)
		}
		if _, err := io.ReadFull(conn, buf[:length]); err != nil {
			return nil, err
		}
		clientRequestMessage.ADDR = string(buf[:length])
	case AddressTypeIPV6:
		buf = make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		clientRequestMessage.ADDR = net.IP(buf).String()
	}

	//读取port
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	clientRequestMessage.PORT = uint16(buf[0])<<8 + uint16(buf[1])

	return clientRequestMessage, nil
}

const (
	RepSucceeded byte = iota
	RepServerFailure
	RepConnectionNotAllowed
	RepNetworkUnreachable
	RepHostUnreachable
	RepConnectionRefused
	RepTTLExpired
	RepCommandNotSupported
	RepAddressTypeNotSupported
)

func replySucceededMessage(writer io.Writer, AddressType byte, ip net.IP, port uint16) error {
	_, err := writer.Write([]byte{Socks5Version, RepSucceeded, Socks5Reserved, AddressType})
	if err != nil {
		return err
	}

	if _, err = writer.Write(ip); err != nil {
		return err
	}

	b := bytes.NewBuffer([]byte{})
	if err = binary.Write(b, binary.BigEndian, port); err != nil {
		return err
	}
	_, err = writer.Write(b.Bytes())
	return err
}

func replyFailureMessage(writer io.Writer, failureType byte) error {
	_, err := writer.Write([]byte{Socks5Version, failureType, Socks5Reserved, byte(AddressTypeIPV4), 0, 0, 0, 0, 0, 0, 0})
	return err
}
