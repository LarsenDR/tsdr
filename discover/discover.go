package main

import (
	"flag"
	"fmt"
	"net"
	//"github.com/kv0s/tsdr/hpsdrp1"
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

	fmt.Printf("%#v\n", len(intr))

	for i := range intr {
		fmt.Printf("%#v\n", intr[i].Name)
	}

	return err
}

// Discover send the Discovery packet to an interface.
func (d *Radiobd) Discover() (err error) {
	return err
}

//==============================================
const version string = "0.0.1"
const started string = "2020-11-03"
const update string = "2020-11.03"

func usage() {
	fmt.Printf("discover  version:(%s)\n", version)
	fmt.Printf("    By Dave KV0S, %s, GPL3 \n", started)
	fmt.Printf("    Last Updated: %s \n\n", update)
}

func main() {
	var infc *Intface

	//ifn := flag.String("interface", "none", "Select one interface")
	//veb := flag.Bool("verbose", false, "Select true or false")

	flag.Parse()

	if flag.NFlag() < 1 {
		usage()
	}

	err := infc.Interface()
	if err != nil {
		fmt.Errorf("%s", err)
	}
}
