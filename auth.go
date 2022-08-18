package socks5

import (
	"errors"
	"io"
)

type Method = byte

// 协商消息
type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

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
	if buf[0] != SOCKS5Version {
		return nil, errors.New("protocol version not supported")
	}

	//第二位是支持多少认证方法
	nMethods := buf[1]
	buf = make([]Method, nMethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nMethods,
		Methods:  buf,
	}, nil
}
