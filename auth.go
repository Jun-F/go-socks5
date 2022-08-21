package socks5

import (
	"io"
)

type Method = byte

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPASSWORD     Method = 0x02
	MethodNOACCEPTABLE Method = 0xff
)

// 协商消息
type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

// 接收客户端消息
func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	//io.ReadFull 从指定的读取器r读取到指定的缓冲区buf
	//返回指定缓冲区复制的字节数，如果读取的字节数小于指定缓冲区的长度，则返回错误
	//当且仅当没有读取字节时，返回的错误是“EOF”
	//这里读取Version和NMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	//socks5第一位是版本
	if buf[0] != Socks5Version {
		return nil, ErrVersionNotSupported
	}

	//第二位是支持多少认证方法
	nMethods := buf[1]
	buf = make([]Method, nMethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  Socks5Version,
		NMethods: nMethods,
		Methods:  buf,
	}, nil
}

// 服务端返回消息
func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{Socks5Version, method}
	_, err := conn.Write(buf)
	return err
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

const passwordAuthVersion byte = 0x01
const (
	passwordAuthSucceeded byte = 0x00
	passwordAuthFailure   byte = 0x01
)

// 用户名密码认证消息
func NewPasswordAuthMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version, ulen := buf[0], buf[1]
	if version != passwordAuthVersion {
		return nil, ErrMethodVersionNotSupported
	}

	//读取username
	if int(ulen) > len(buf) {
		buf = make([]byte, ulen+1)
	}

	if _, err := io.ReadFull(conn, buf[:ulen+1]); err != nil {
		return nil, err
	}
	username := string(buf[:ulen])

	//读取password
	plen := buf[ulen]
	if int(plen) > len(buf) {
		buf = make([]byte, plen)
	}

	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return nil, err
	}
	password := string(buf[:plen])

	return &ClientPasswordMessage{username, password}, nil
}

func NewServerPasswordAuthMessage(conn io.Writer, status byte) error {
	buf := []byte{passwordAuthVersion, status}
	_, err := conn.Write(buf)
	return err
}
