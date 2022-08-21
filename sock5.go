package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

const (
	Socks5Version  byte = 0x05
	Socks5Reserved byte = 0x00
)

var (
	ErrVersionNotSupported       = errors.New("protocol version not supported")
	ErrMethodVersionNotSupported = errors.New("method version not supported")
	ErrCommandNotSupported       = errors.New("request command not supported")
	ErrReservedNotSupported      = errors.New("request reserved not supported")
	ErrAddressTypeNotSupported   = errors.New("request addressType not supported")
)

type Server interface {
	Run() error
}

type Socks5Server struct {
	IP     string
	Port   int
	Config *Config
}

type Config struct {
	AuthMethod    Method
	PasswordCheck func(username string, password string) bool
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
			err := handleConnection(conn, s.Config)
			if err != nil {
				log.Printf("handle Connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

// 处理请求
func handleConnection(conn net.Conn, config *Config) error {
	//协商过程
	if err := auth(conn, config); err != nil {
		return err
	}

	//请求过程
	targetConn, err := request(conn)
	if err != nil {
		return err
	}

	//转发过程
	return forward(conn, targetConn)
}

func auth(conn net.Conn, config *Config) error {
	clientAuthMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	var acceptable bool
	for _, method := range clientAuthMessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
			break
		}
	}

	if !acceptable {
		err := NewServerAuthMessage(conn, MethodNOACCEPTABLE)
		if err != nil {
			return err
		}
		return errors.New("No Acceptable Method")
	}

	if err = NewServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}

	//如果不是noAUth，进行认证
	if config.AuthMethod == MethodPASSWORD {
		passwordMsg, err := NewPasswordAuthMessage(conn)
		if err != nil {
			return err
		}

		if !config.PasswordCheck(passwordMsg.Username, passwordMsg.Password) {
			return NewServerPasswordAuthMessage(conn, passwordAuthFailure)
		}

		if err = NewServerPasswordAuthMessage(conn, passwordAuthSucceeded); err != nil {
			return err
		}
	}

	return nil
}

func request(conn net.Conn) (io.ReadWriteCloser, error) {
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}

	if message.CMD == CommandBind {
		return nil, replyFailureMessage(conn, RepCommandNotSupported)
	}
	if message.AddressType == AddressTypeIPV6 {
		return nil, replyFailureMessage(conn, RepAddressTypeNotSupported)
	}

	//请求目标网站
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", message.ADDR, message.PORT))
	if err != nil {
		return nil, replyFailureMessage(conn, RepConnectionRefused)
	}

	addr := targetConn.LocalAddr().(*net.TCPAddr)
	return targetConn, replySucceededMessage(conn, byte(message.AddressType), addr.IP, message.PORT)
}

func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	//io.Copy会阻塞，使用goroutine进行同时接收和发送数据
	defer targetConn.Close()
	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}
