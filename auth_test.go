package socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a ClientAuthMessage", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, 0x00, 0x01}
		r := bytes.NewReader(b)

		message, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatal(err)
		}

		if message.Version != SOCKS5Version {
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
		b := []byte{SOCKS5Version, 2, 0x00}
		r := bytes.NewReader(b)

		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("shoud get err != nil but got nil")
		}
	})
}
