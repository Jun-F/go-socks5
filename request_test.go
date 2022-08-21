package socks5

import (
	"bytes"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	tests := []struct {
		Version     byte
		CMD         Command
		AddressType AddressType
		ADDR        []byte
		PORT        []byte
		Err         error
		Message     ClientRequestMessage
	}{
		{
			Version:     Socks5Version,
			CMD:         CommandConnect,
			AddressType: AddressTypeIPV4,
			ADDR:        []byte{126, 25, 45, 132},
			PORT:        []byte{0x00, 0x50},
			Err:         nil,
			Message:     ClientRequestMessage{Socks5Version, CommandConnect, Socks5Reserved, AddressTypeIPV4, "126.25.45.132", 0x0050},
		},
		{
			Version:     0x04,
			CMD:         CommandConnect,
			AddressType: AddressTypeIPV4,
			ADDR:        []byte{126, 25, 45, 132},
			PORT:        []byte{0x00, 0x50},
			Err:         ErrVersionNotSupported,
			Message:     ClientRequestMessage{},
		},
		{
			Version:     Socks5Version,
			CMD:         CommandConnect,
			AddressType: AddressTypeIPV6,
			ADDR:        []byte{0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0xB3, 0xFF, 0xFE, 0x1E, 0x83, 0x29},
			PORT:        []byte{0x00, 0x50},
			Err:         nil,
			Message:     ClientRequestMessage{Socks5Version, CommandConnect, Socks5Reserved, AddressTypeIPV4, "FE80::0202:B3FF:FE1E:8329", 0x0050},
		},
		{
			Version:     Socks5Version,
			CMD:         CommandConnect,
			AddressType: AddressTypeDomain,
			ADDR:        []byte{13, 119, 119, 119, 46, 98, 97, 105, 100, 117, 46, 99, 111, 109},
			PORT:        []byte{0x00, 0x50},
			Err:         nil,
			Message:     ClientRequestMessage{Socks5Version, CommandConnect, Socks5Reserved, AddressTypeIPV4, "www.baidu.com", 0x0050},
		},
	}

	for _, test := range tests {
		b := bytes.NewBuffer([]byte{test.Version, byte(test.CMD), Socks5Reserved, byte(test.AddressType)})
		b.Write(test.ADDR)
		b.Write(test.PORT)

		message, err := NewClientRequestMessage(b)
		if err != test.Err {
			t.Fatalf("should get error %s but got %s\n", test.Err, err)
		}
		if err != nil {
			return
		}

		if *message != test.Message {
			t.Fatalf("should get Message %v but got %v\n", test.Message, message)
		}

	}
}
