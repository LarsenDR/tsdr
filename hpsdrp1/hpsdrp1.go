package hpsdrp1

import (
	"fmt"
	"net"
)

// Intface structure
type Intface struct {
	Intname   string
	MAC       string
	Ipv4      string
	Mask      []byte
	Network   string
	Ipv6      string
	Ipv4Bcast string
}

//Radiobd structure
type Radiobd struct {
	Status     string
	Board      string
	Protocol   string
	Baddress   string
	Bport      string
	Pcaddress  string
	Macaddress string
	Firmware   string
}

// Interface determines the network interfaces connect to this machine.
func (infc *Intface) Interface() (err error) {
	intr, er := net.Interfaces()
	if er != nil {
		err = fmt.Errorf("Interface error %v", err)
		return err
	}

	fmt.Printf("%#v\n", intr)
	return err
}

// Discover send the Discovery packet to an interface.
func (d *Radiobd) Discover() (err error) {
	return err
}
