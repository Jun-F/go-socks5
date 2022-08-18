package socks5

import (
	"fmt"
	"log"
	"net"
)

const SOCKS5Version = 0x05

type Server interface {
	Run() error
}

type Socks5Server struct {
	IP   string
	Port int
}

func (s *Socks5Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Connection failure from %s: %s", conn.RemoteAddr(), err)
			continue
		}

		go func() {
			defer conn.Close()
			err := handleConnection(conn)
			if err != nil {
				log.Printf("handle Connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

// 处理请求
func handleConnection(conn net.Conn) error {
	//协商过程
	if err := auth(conn); err != nil {
		return err
	}

	//请求过程

	//转发过程

	return nil
}

func auth(conn net.Conn) error {

	return nil
}
