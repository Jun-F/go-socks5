package socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a ClientAuthMessage", func(t *testing.T) {
		b := []byte{Socks5Version, 2, MethodNoAuth, MethodGSSAPI}
		r := bytes.NewReader(b)

		message, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatal(err)
		}

		if message.Version != Socks5Version {
			t.Fatalf("want SOCKS5Version but got %d", message.Version)
		}

		if message.NMethods != 2 {
			t.Fatalf("want NMethods = 2 but got %d", message.NMethods)
		}

		if !reflect.DeepEqual(message.Methods, []byte{0x00, 0x01}) {
			t.Fatalf("want Methods = %v but got %v", []byte{0x00, 0x01}, message.NMethods)
		}
	})

	t.Run("methods lenght is shorter than nmethods", func(t *testing.T) {
		b := []byte{Socks5Version, 2, 0x00}
		r := bytes.NewReader(b)

		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("shoud get err != nil but got nil")
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("should pass", func(t *testing.T) {
		w := bytes.NewBuffer(make([]byte, 2))
		err := NewServerAuthMessage(w, MethodNoAuth)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestNewPasswordAuthMessage(t *testing.T) {
	tests := []struct {
		Version byte
		ULEN    byte
		UNAME   []byte
		PLEN    byte
		PASSWD  []byte
		Err     error
		Msg     ClientPasswordMessage
	}{
		{passwordAuthVersion, 5, []byte{98, 97, 105, 100, 117}, 5, []byte{98, 97, 105, 100, 117}, nil, ClientPasswordMessage{"baidu", "baidu"}},
	}

	for _, test := range tests {
		b := bytes.NewBuffer([]byte{test.Version, test.ULEN})
		b.Write(test.UNAME)
		b.Write([]byte{test.PLEN})
		b.Write(test.PASSWD)

		message, err := NewPasswordAuthMessage(b)
		if err != test.Err {
			t.Fatalf("should get error %s but got %s\n", test.Err, err)
		}
		if err != nil {
			return
		}

		if *message != test.Msg {
			t.Fatalf("should get Message %v but got %v\n", test.Msg, message)
		}
	}
}

func TestNewServerPasswordAuthMessage(t *testing.T) {
	tests := []struct {
		status byte
		Err    error
	}{
		{passwordAuthSucceeded, nil},
	}

	for _, test := range tests {
		b := bytes.NewBuffer(make([]byte, 2))
		err := NewServerPasswordAuthMessage(b, test.status)
		if err != test.Err {
			t.Fatalf("should get error %s but got %s\n", test.Err, err)
		}
	}
}
