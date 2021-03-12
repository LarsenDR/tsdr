package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
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

// Interfaces determines the network interfaces connect to this machine.
func Interfaces() (Intfc []Intface, err error) {

	intr, er := net.Interfaces()
	if er != nil {
		err = fmt.Errorf("Interface error %v", err)
		return nil, err
	}

	Intfc = make([]Intface, len(intr))

	for i := range intr {
		//fmt.Println(intr[i].Name, intr[i].HardwareAddr)
		Intfc[i].Intname = intr[i].Name
		Intfc[i].MAC = intr[i].HardwareAddr.String()
		aad, err := intr[i].Addrs()
		if err != nil {
			err = fmt.Errorf("Interface error %v", err)
			return Intfc, err
		}

		Intfc[i].Intname = intr[i].Name

		for j := range aad {
			ip := net.ParseIP(aad[j].String())
			str := aad[j].String()

			//var ip net.IP
			if strings.Contains(str, ".") {
				//ip, _, err := net.ParseCIDR(aad[j].String())
				//ip := net.ParseIP(aad[j].String())
				if runtime.GOOS == "windows" {
					ip = net.ParseIP(aad[j].String())
					Intfc[i].Ipv4 = aad[j].String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else if runtime.GOOS == "darwin" {
					ip = net.ParseIP(aad[j].String())
					adstring := strings.Split(aad[j].String(), "/")
					Intfc[i].Ipv4 = adstring[0]
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else {
					ip, _, err = net.ParseCIDR(aad[0].String())
					Intfc[i].Ipv4 = ip.String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				}
				if er != nil {
					err = fmt.Errorf("Parce IP error %v", er)
					return Intfc, err
				}

				str := strings.Split(Intfc[i].Ipv4, ".")
				var ipd []string
				ipd = append(ipd, string(str[0]), string(str[1]), string(str[2]), "255")
				//ipd = append(ipd, "255", "255", "255", "255")
				Intfc[i].Ipv4Bcast = strings.Join(ipd, ".")
			} else {
				if runtime.GOOS == "windows" {
					ip = net.ParseIP(aad[j].String())
					Intfc[i].Ipv4 = aad[j].String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else if runtime.GOOS == "darwin" {
					ip = net.ParseIP(aad[j].String())
					Intfc[i].Ipv4 = aad[j].String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else {
					ip, _, err = net.ParseCIDR(aad[0].String())
					Intfc[i].Ipv4 = ip.String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				}

				if er != nil {
					err = fmt.Errorf("Parce IP error %v", er)
					return Intfc, err
				}
				//ip, _, err = net.ParseCIDR(aad[1].String())
				//Intfc[i].Ipv6 = ip.To6()
			}
		}
	}
	return Intfc, err
}

//Hpsdrboard structure
type Hpsdrboard struct {
	Status     string
	Board      string
	Protocol   string
	Baddress   string
	Bport      string
	Pcaddress  string
	Macaddress string
	Firmware   string
}

// Discover send the Discovery packet to an interface.
func Discover(addrStr string, bcastStr string, ddelay int, debug string) (strs []Hpsdrboard, err error) {
	var b []byte
	var c []byte
	var str Hpsdrboard

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	b, er := hex.DecodeString("effe02")
	if er != nil {
		err = fmt.Errorf(" %v", er)
		return nil, err
	}

	//b = append(b, st)

	for i := len(b); i < 64; i++ {
		b = append(b, 0x00)
	}

	bcast, er := net.ResolveUDPAddr("udp", bcastStr)
	if er != nil {
		err = fmt.Errorf("Broadcast Address not resolved %v", er)
		return nil, err
	}

	//fmt.Println(addrStr, bcastStr)
	addr, er := net.ResolveUDPAddr("udp", addrStr)
	if er != nil {

	}

	l, er := net.ListenUDP("udp", addr)
	if er != nil {
		err = fmt.Errorf("ListenUDP er{ror %v", er)
		return nil, err
	}
	defer l.Close()

	k, er := l.WriteToUDP(b, bcast)

	if er != nil {
		err = fmt.Errorf("Broadcast not connected %v, %v", k, er)
		return nil, err
	}

	if strings.Contains(debug, "hex") {
		fmt.Println("Discovery ")
		fmt.Printf("sent : %s: %x : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Discover ")
		fmt.Printf("sent : %s: %v : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	}
	l.SetReadDeadline(time.Time(time.Now().Add(time.Duration(ddelay) * time.Second)))

	//fmt.Println( "Before the loop" )
	for i := 0; i < 10; i++ {
		_, ad, _ := l.ReadFromUDP(c)

		if ad != nil {
			if strings.Contains(debug, "hex") {
				fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
			} else if strings.Contains(debug, "dec") {
				fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
			}
			str.Protocol = "p1"
			str.Pcaddress = addrStr

			if c[2] == 2 {
				str.Status = "idle"
			} else if c[2] == 3 {
				str.Status = "running"
			}

			str.Macaddress = fmt.Sprintf("%x:%x:%x:%x:%x:%x", c[3], c[4], c[5], c[6], c[7], c[8])

			if c[10] == 0x00 {
				str.Board = "Metis"
			} else if c[10] == 0x01 {
				str.Board = "Hermes"
			} else if c[10] == 0x02 {
				str.Board = "Griffin"
			} else if c[10] == 0x03 {
				str.Board = "Unknown"
			} else if c[10] == 0x04 {
				str.Board = "Angelia"
			} else if c[10] == 0x05 {
				str.Board = "Orion"
			} else if c[10] == 0x06 {
				str.Board = "Hermes-lite"
			} else if c[10] == 0x0a {
				str.Board = "TangerineSDR"
			}

			str.Firmware = fmt.Sprintf("%d.%d", c[9]/10, c[9]%10)

			st := strings.Split(ad.String(), ":")
			str.Baddress = st[0]
			str.Bport = st[1]

			strs = append(strs, str)
		}
	}
	//fmt.Println( "After the loop")

	return strs, err

}

//Setip function sets a new fixed ip for the HPSDR board on your domain.
func Setip(newip string, str Hpsdrboard, debug string, check bool) (st Hpsdrboard, err error) {
	var b []byte
	var c []byte

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	b, er := hex.DecodeString("effe03")
	if er != nil {
		err = fmt.Errorf("Hex decode error %v", er)
		return str, err
	}

	macstr := strings.Split(str.Macaddress, ":")
	//fmt.Println("length of macstr ", len(macstr), macstr)

	for i := 0; i < len(macstr); i++ {
		m := []byte(macstr[i])
		if len(m) < 2 {
			m = []byte("0")
			m = append(m, []byte(macstr[i])[0])
		}
		mm := make([]byte, len(m))
		_, er := hex.Decode(mm, m)
		if er != nil {
			err = fmt.Errorf("Hex decode error %v", er)
			return str, err
		}
		//fmt.Println("index ", i, m, mm)
		b = append(b, mm[0])
	}

	ipstr := strings.Split(newip, ".")
	if len(ipstr) != 4 {
		return str, fmt.Errorf("proposed IPV4 address has %d numbers, must be 4 numbers", len(ipstr))
	}
	ipad := net.ParseIP(str.Baddress)
	msk := ipad.DefaultMask()
	netw := ipad.Mask(msk).String()

	//fmt.Println("newip ", newip, !strings.Contains(newip, "255.255.255.255"))
	check = !strings.Contains(newip, "255.255.255.255")

	if check {
		ntipstr := strings.Split(netw, ".")
		//fmt.Println("length of newip ", len(ipstr), ipstr)
		for i := 0; i < len(ipstr); i++ {
			m, er := strconv.Atoi(ipstr[i])
			if er != nil {
				err = fmt.Errorf("IPv4 string decode error %v", er)
				return str, err
			}
			nm, er := strconv.Atoi(ntipstr[i])
			if er != nil {
				err = fmt.Errorf("IPv4 string decode error %v", er)
				return str, err
			}
			if i == 0 {
				if m == 127 {
					return str, fmt.Errorf("127 reserved for localhost")
				} else if m == 224 {
					return str, fmt.Errorf("224 reserved")
				} else if m == 224 {
					return str, fmt.Errorf("224 reserved")
				} else if m == 169 {
					return str, fmt.Errorf("169 reserved for adhoc networks")
				} else if m == 240 {
					return str, fmt.Errorf("240 reserved")
				}
			}
			if (m != nm) && (nm != 0) {
				return str, fmt.Errorf("changing subnet is not recommended")
			}
			//fmt.Println("index ", i, m, ipstr[i])
			b = append(b, byte(m))
		}
	}

	for i := 9; i < 64; i++ {
		if i > 12 {
			b = append(b, 0x00)
		}
	}

	//pcaddr := fmt.Sprintf("%s:%s", str.Pcaddress, "1024")
	addr, er := net.ResolveUDPAddr("udp", str.Pcaddress)
	if er != nil {
		err = fmt.Errorf("Address not resolved %v", er)
		return str, err
	}

	bcast, er := net.ResolveUDPAddr("udp", "255.255.255.255:1024")
	if er != nil {
		err = fmt.Errorf("broadcast not resolved %v", er)
		return str, err
	}

	l, er := net.ListenUDP("udp", addr)
	if er != nil {
		err = fmt.Errorf("ListenUDP error %v", er)
		return str, err
	}
	defer l.Close()

	k, er := l.WriteToUDP(b, bcast)
	if er != nil {
		err = fmt.Errorf("broadcast string not connected %v %v", k, er)
		return str, err
	}
	if strings.Contains(debug, "hex") {
		fmt.Println("Set IP ")
		fmt.Printf("sent : %s: %x : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Set IP ")
		fmt.Printf("sent : %s: %v : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	}
	l.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

	_, ad, _ := l.ReadFromUDP(c)

	if strings.Contains(debug, "hex") {
		fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
		fmt.Println(" ")
	}

	err = nil
	return str, err
}

// Programboard sends a new RBF file to the HPSDR board flash memory.
func Programboard(str Hpsdrboard, input string, debug string) error {
	//var output string
	//output = "output"
	var er error

	// Open the RBF file
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		err := f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// calculate the Statistics of the RBF file
	fi, err := f.Stat()
	if err != nil {
		fmt.Println("Could not open the file")
	}

	fmt.Println("\n      Programming the HPSDR Board")
	packets := math.Ceil(float64(fi.Size()) / 256.0)
	fmt.Println("    Found rbf file:", input)
	fmt.Println("     Size rbf file:", fi.Size())
	fmt.Println("Size rbf in memory:", ((fi.Size()+255)/256)*256)
	fmt.Println("           Packets:", packets)
	fmt.Println(" ")
	fmt.Printf("           Percent:     ")

	// make a read buffer
	r := bufio.NewReader(f)
	// open output file  THIS CODE USED FOR FILE WRITE OUT OR TESTING
	//fo, err := os.Create(outpustr.Boardstr.Boardstr.Boardstr.Boardit)
	//if err != nil {
	///		log.Fatal(err)
	//	}

	//	defer func() {
	//		err := fo.Close()
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//	}()

	// make a write buffer
	//w := bufio.NewWriter(fo)

	// Open the UDP connections
	addr, err := net.ResolveUDPAddr("udp", str.Pcaddress)
	if err != nil {
		fmt.Println(" Addr not resolved ", err)
	}

	bdaddr := fmt.Sprintf("%s:%s", str.Baddress, "1024")
	baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	if err != nil {
		fmt.Println(" Baddr not resolved ", err)
	}

	//l, err := net.ListenUDP("udp", addr)
	//if err != nil {
	//	fmt.Println(" ListenUDP error ", err)
	//}

	//defer l.Close()

	w, err := net.DialUDP("udp", addr, baddr)
	if err != nil {
		fmt.Println(" DialUDP error ", err)
	}

	defer w.Close()

	// make a buffer to keep chunks that are read
	buf := make([]byte, 256)
	var b []byte
	p := make([]byte, 4)

	pk := int(packets)
	p[0] = byte((pk >> 24) & 0xff)
	p[1] = byte((pk >> 16) & 0xff)
	p[2] = byte((pk >> 8) & 0xff)
	p[3] = byte(pk & 0xff)

	//totalnb := float64(fi.Size())
	tpk := 0
	for {
		// read a chunk
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}

		if n == 0 {
			break
		}

		if n < 256 {
			for i := n; i < 256; i++ {
				buf[i] = 0xFF
			}
			n = 256
		}

		b, err = hex.DecodeString(fmt.Sprintf("effe0301%x", string(p)))
		if err != nil {
			fmt.Println("Hex decode error", err)
		}

		b = append(b, buf...)

		//nb, err := PackettoFile(str, b, w, debug, tpk)
		_, err = PackettoUDP(str, b, w, debug, tpk)
		if err != nil {
			fmt.Println("Read Error:", err)
		}

		tpk++
		if debug == "none" {
			pct := (float64(tpk) / packets) * 100.0
			fmt.Printf("\b\b\b\b%4.0f", pct)
		}
	}
	fmt.Println("\n      Programming Done")

	er = nil
	return er
}

//PackettoFile sends on 256 packet formatted for programming to a file for testing.
func PackettoFile(str Hpsdrboard, buf []byte, w *bufio.Writer, debug string, tpk int) (int, error) {

	// debug prints
	if debug == "hex" {
		fmt.Println("Program Board ")
		fmt.Printf("sent : %s: %x : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	} else if debug == "dec" {
		fmt.Println("Program Board")
		fmt.Printf("sent : %s: %v : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	}

	// write a chunk
	nb, err := w.Write(buf[9:])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(" ")

	err = w.Flush()
	if err != nil {
		log.Fatal(err)
	}

	var er error
	er = nil
	return nb, er
}

//PackettoUDP sends one 256 packet formatted for programming to a UDP address.
func PackettoUDP(str Hpsdrboard, buf []byte, w *net.UDPConn, debug string, tpk int) (int, error) {
	//var b []byte
	var c []byte = make([]byte, 64, 64)
	// debug prints
	if debug == "hex" {
		fmt.Println("Program Board ")
		fmt.Printf("sent : %s: %x : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	} else if debug == "dec" {
		fmt.Println("Program Board")
		fmt.Printf("sent : %s: %v : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	}

	//bdaddr := fmt.Sprintf("%s:%s", str.Baddress, str.Bport)
	//baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	k, err := w.Write(buf)
	if err != nil {
		fmt.Println(" address not connected ", k, err)
	}

	//	for {
	//	w.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

	n, ad, err := w.ReadFromUDP(c)
	if err != nil {
		return 3, err
	}

	if n > 0 {

		if debug == "hex" {
			fmt.Printf("received : %s: on %s %x : length=%d\n", ad, str.Pcaddress, c, len(c))
			fmt.Println(" ")
		} else if debug == "dec" {
			fmt.Printf("received : %s: on %s %v : length=%d\n", ad, str.Pcaddress, c, len(c))
			fmt.Println(" ")
		}
	} else {
		fmt.Printf("received : Time out %s on %s %v : length=%d\n", ad, str.Pcaddress, c, len(c))
		fmt.Println(" ")
	}

	//}
	var er error
	er = nil
	return 3, er
}

//Erasestatus structure
type Erasestatus struct {
	Seconds int
	State   error
}

//Eraseboard sends the erase command to the HPSDR board direst writes
func Eraseboard(str Hpsdrboard, input string, edelay int, debug string) (erstat Erasestatus, err error) {
	var b []byte
	var c []byte

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	// Open the RBF file and close it, we do not want to coninue is file does not exist.
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}

	err = f.Close()
	if err != nil {
	}

	if debug == "none" {
		erstat.State = fmt.Errorf("erasing the hpsdr board")
	}

	b, er := hex.DecodeString("effe0302")
	if er != nil {
		fmt.Println("Hex decode error", er)
		err = fmt.Errorf("hex decode error %v", er)
		return erstat, err
	}

	for i := 4; i < 64; i++ {
		b = append(b, 0x00)
	}

	addr, err := net.ResolveUDPAddr("udp", str.Pcaddress)
	if err != nil {
		fmt.Println(" Addr not resolved ", err)
		err = fmt.Errorf("address not resolved %v", er)
		return erstat, err
	}

	bdaddr := fmt.Sprintf("%s:%s", str.Baddress, "1024")
	baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	if err != nil {
		fmt.Println(" Baddr not resolved ", err)
		err = fmt.Errorf("broadcast not resolved %v", er)
		return erstat, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		err = fmt.Errorf("listenUDP error %v", er)
		return erstat, err
	}
	defer l.Close()

	k, err := l.WriteToUDP(b, baddr)
	if err != nil {
		err = fmt.Errorf("address not connected %v %v", k, er)
		return erstat, err
	}

	if strings.Contains(debug, "hex") {
		fmt.Println("Erasing Board ")
		fmt.Printf("sent : %s: %x : length=%d\n", baddr, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Erasing Board")
		fmt.Printf("sent : %s: %v : length=%d\n", baddr, b, len(b))
		fmt.Println(" ")
	}

	fmt.Print("           Seconds:     ")
	for i := 0; i < edelay; i++ {
		l.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

		n, ad, _ := l.ReadFromUDP(c)

		fmt.Printf("\b\b\b\b%4d", i)
		erstat.Seconds = i
		if n > 0 {
			if strings.Contains(debug, "hex") {
				fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
				i = edelay
				break
			} else if strings.Contains(debug, "dec") {
				fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
				i = edelay
				break
			} else if debug == "none" {
				erstat.State = fmt.Errorf("Erasing Done")
				i = edelay
				break
			}
		} else if i+1 == edelay {
			//fmt.Printf("\n      Timeout at %s Seconds\n", edelay)
			erstat.State = fmt.Errorf("timeout at %d Seconds", edelay)
			return erstat, fmt.Errorf("timeout at %d Seconds", edelay)
		} else {
			fmt.Printf("\b\b\b\b%4d", i)
		}
	}

	err = nil
	return erstat, err

}

// Program to program HPSDR boards from the command line
//
// by David R. Larsen KV0S, Copyright 2014-11-24
//

const version string = "0.1.4"
const update string = "2020-10-24"

// function to point users to the command list
func usage() {
	fmt.Printf("    For a list of commands use -help \n\n")
}

// Function to print the program name info
func program() {
	fmt.Printf("CmdHPSDRProgrammer  version:(%s)\n", version)
	fmt.Printf("    By Dave KV0S, 2014-11-24, GPL2 \n")
	fmt.Printf("    Last Updated: %s \n\n", update)
}

// Listboard is a convenience function to print board data
func Listboard(str Hpsdrboard) {
	if str.Macaddress != "0:0:0:0:0:0" {
		fmt.Printf("       HPSDR Board: (%s)\n", str.Macaddress)
		fmt.Printf("              IPV4: %s\n", str.Baddress)
		fmt.Printf("              Port: %s\n", str.Bport)
		fmt.Printf("              Type: %s\n", str.Board)
		fmt.Printf("          Firmware: %s\n", str.Firmware)
		fmt.Printf("            Status: %s\n\n", str.Status)
		fmt.Printf("            PC    : %s\n\n", str.Pcaddress)
	}
}

//Listinterface is a convenience function to print interface data
func Listinterface(itr Intface) {
	fmt.Printf("          Computer: (%v)\n", itr.MAC)
	fmt.Printf("                OS: %s (%s) %d CPU(s)\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("              IPV4: %v\n", itr.Ipv4)
	fmt.Printf("              Mask: %d\n", itr.Mask)
	fmt.Printf("           Network: %v\n", itr.Network)
	fmt.Printf("              IPV6: %v\n\n", itr.Ipv6)
}

//Listflags is a convienience function to print flag data
func Listflags(fg flagsettings) {
	fmt.Printf("	Saved settings: \n")
	fmt.Printf(" 		 Interface: %v\n", fg.Intface)
	fmt.Printf("          Filename: %v\n", fg.Filename)
	fmt.Printf("      Selected MAC: (%v)\n", fg.SelectMAC)
	fmt.Printf("            SetRBF: %v\n", fg.SetRBF)
	fmt.Printf("             Debug: %v\n", fg.Debug)
	fmt.Printf("            Ddelay: %d\n\n", fg.Ddelay)
	fmt.Printf("            Edelay: %d\n\n", fg.Edelay)
}

//Listflagstemp is a convienience function to print temporary flag data
func Listflagstemp(fgt flagtemp) {
	fmt.Printf("     Temp settings: \n")
	fmt.Printf("          Settings: %v\n", fgt.Settings)
	fmt.Printf("             SetIP: %v\n", fgt.SetIP)
	fmt.Printf("              Save: %v\n", fgt.Save)
	fmt.Printf("              Load: %v\n\n", fgt.Load)
}

// Initflags is a convienience function to initialize command line flags
func Initflags(fg *flagsettings) {
	fg.Intface = "none"
	fg.Filename = "none"
	fg.SelectMAC = "none"
	fg.SetRBF = "none"
	fg.Debug = "none"
	fg.Ddelay = 2
	fg.Edelay = 60
}

//flagsetting is a local structure to work with command line flags
type flagsettings struct {
	Filename  string
	Intface   string
	SelectMAC string
	SetRBF    string
	Debug     string
	Ddelay    int
	Edelay    int
}

//flagtemp is a local structure to work with command line temp flags
type flagtemp struct {
	SetIP    string
	Settings string
	Save     string
	Load     string
}

//Initflagstemp is a function to initialize the temp flags
func Initflagstemp(fgt *flagtemp) {
	fgt.SetIP = "none"
	fgt.Settings = "none"
	fgt.Save = "none"
	fgt.Load = "none"
}

//Parseflagstruct is a function to parse input flags
func Parseflagstruct(fg *flagsettings, fgt *flagtemp, ifn string, stmac string, stip string, stport string, strbf string, db string, ss string, sv string, ld string, dd int, ed int) {

	Initflags(fg)
	Initflagstemp(fgt)

	if (ld == "default") || (ld == "Default") {
		fg.Filename = "CmdHPSDRProgrammer.json"
	} else if ld != "none" {
		fg.Filename = ld
	}

	if ld != "none" {

		dta, _ := ioutil.ReadFile(fg.Filename)
		err := json.Unmarshal(dta, &fg)
		if err != nil {
			fmt.Println("error:", err)
		}
	}

	if ifn != "none" {
		fg.Intface = ifn
	}
	if stmac != "none" {
		fg.SelectMAC = stmac
	}
	if strbf != "none" {
		fg.SetRBF = strbf
	}
	if db != "none" {
		fg.Debug = db
	}
	if ed != 20 {
		fg.Edelay = ed
	}
	if dd != 2 {
		fg.Ddelay = dd
	}
	if ed != 2 {
		fg.Edelay = ed
	}
	if stip != "none" {
		fgt.SetIP = stip
	}
	if ss != "none" {
		fgt.Settings = ss
	}
	if sv == "default" {
		fgt.Save = sv
		fg.Filename = "CmdHPSDRProgrammer.json"
	} else if ld != "none" {
		fg.Filename = ld
		fgt.Load = ld
	}

	if fgt.Save != "none" {

		f, err := os.Create(fg.Filename)
		if err != nil {
			panic(err)
		}

		b, err := json.MarshalIndent(fg, "", "\t")
		if err != nil {
			log.Fatal(err)
		}

		if err != nil {
			fmt.Println("error:", err)
		}

		fmt.Fprintf(f, "%s\n", b)
	}

	if ss != "none" {
		Listflags(*fg)
		Listflagstemp(*fgt)
	}

}

func main() {
	var fg flagsettings
	var fgt flagtemp
	var erstat Erasestatus

	// Create the command line flags
	ifn := flag.String("interface", "none", "Select one interface")
	stmac := flag.String("selectMAC", "none", "Select Board by MAC address")
	stip := flag.String("setIP", "none", "Set IP address, unused number from your subnet or 0.0.0.0 for DHCP")
	stport := flag.String("setPort", "1024", "Set port number")
	strbf := flag.String("setRBF", "none", "Select the RBF file to write to the board")
	dd := flag.Int("ddelay", 2, "Discovery delay before a rediscovery")
	ed := flag.Int("edelay", 60, "Discovery delay before a rediscovery")
	db := flag.String("debug", "none", "Turn debugging and output type, (none, dec, hex)")
	ss := flag.String("settings", "none", "Show the settings values (show)")
	sv := flag.String("save", "none", "Save these current flags for future use in default or a named file")
	ld := flag.String("load", "none", "Load a saved command file from default or a named file")
	cadr := flag.Bool("checkaddress", true, "check if new address is in subdomain and not restricted space")
	cbad := flag.Bool("checkboard", true, "check if new RBF file name has the same name as the board type")

	flag.Parse()

	if flag.NFlag() < 1 {
		program()
		usage()
	}

	Parseflagstruct(&fg, &fgt, *ifn, *stmac, *stip, *stport, *strbf, *db, *ss, *sv, *ld, *dd, *ed)

	intf, err := Interfaces()
	if err != nil {
		fmt.Println(err)
	}

	if flag.NFlag() < 1 {
		fmt.Printf("Interfaces on this Computer: \n")
	}

	for i := range intf {
		if flag.NFlag() < 1 {
			// if no flags list the interfaces in short form
			fmt.Printf("    %s (%s)\n", intf[i].Intname, intf[i].MAC)
		} else if (flag.NFlag() == 1) && (fg.Intface == "none") {
			if fg.Debug == "none" {
				// if one flag and it is debug = none, list the interface in short form
				fmt.Printf("    %s (%s)\n", intf[i].Intname, intf[i].MAC)
			} else {
				// if one flag and it is debug = dec or hex, list the interface in long form
				fmt.Printf("    %s (%s) %s  %s\n", intf[i].Intname, intf[i].MAC, intf[i].Ipv4, intf[i].Ipv6)
			}
		}

		// if ifn flag matches the current interface
		if fg.Intface == intf[i].Intname {
			if len(intf[i].Ipv4) != 0 {
				if fg.Debug == "none" {
					//list the sending computer information
					Listinterface(intf[i])
				}

				var adr string
				var bcadr string
				adr = intf[i].Ipv4 + ":" + *stport
				bcadr = intf[i].Ipv4Bcast + ":" + *stport

				// perform a discovery
				str, err := Discover(adr, bcadr, fg.Ddelay, fg.Debug)
				if err != nil {
					fmt.Println("Error ", err)
				}

				var bdid int
				bdid = 0
				//loop throught the list of discovered HPSDR boards
				for i := 0; i < len(str); i++ {
					if fg.SelectMAC == str[i].Macaddress {
						// if a MAC is selected
						fmt.Printf("      Selected MAC: (%s) %s\n", fg.SelectMAC, str[i].Board)
						bdid = i
					}
				}

				if (len(str) > 0 && fgt.SetIP != str[bdid].Baddress) && (fgt.SetIP != "none") {
					//If the IPV4 changes
					if strings.Contains(*stip, "255.255.255.255") {
						fmt.Printf("     Changing IP address from %s to DHCP address\n\n", str[bdid].Baddress)
					} else {
						fmt.Printf("     Changing IP address from %s to %s\n\n", str[bdid].Baddress, *stip)
					}

					str2, err := Setip(fgt.SetIP, str[bdid], fg.Debug, *cadr)
					if err != nil {
						fmt.Printf("Error %v", str2)
						panic(err)
					}

					// perform a rediscovery
					time.Sleep(time.Duration(fg.Ddelay) * time.Second)
					str, err = Discover(adr, bcadr, fg.Ddelay, fg.Debug)
					if err != nil {
						fmt.Println("Error ", err)
					}

					//loop throught the list of discovered HPSDR boards
					for i := 0; i < len(str); i++ {
						if fg.SelectMAC == str[i].Macaddress {
							// if a MAC is selected
							//fmt.Printf("      Selected MAC: %s\n", fg.SelectMAC)
							bdid = i
						}
					}
				}
				if *strbf != "none" {
					if *cbad && (fg.SelectMAC != "none") && (fg.SelectMAC == str[bdid].Macaddress) {
						if strings.Contains(strings.ToLower(*strbf), strings.ToLower(str[bdid].Board)) {
							// erasy the board flash memory
							erstat, err = Eraseboard(str[bdid], fg.SetRBF, fg.Edelay, fg.Debug)
							if err != nil {
								panic(err)
							} else {
								fmt.Printf(" %v %v\n", erstat.Seconds, erstat.State)
								// send the RBF to the flash memory
								Programboard(str[bdid], fg.SetRBF, fg.Debug)
							}
						} else {
							fmt.Printf("\n      Input Check: RBF name \"%s\" and selectedMAC board name \"%s\" (%s) do not match!\n", *strbf, str[bdid].Board, str[bdid].Macaddress)
							fmt.Println("       Please correct to program the board.\n")
						}
					} else {
						// easy the board flash memory
						erstat, err = Eraseboard(str[bdid], fg.SetRBF, fg.Edelay, fg.Debug)
						if err != nil {
							panic(err)
						} else {
							fmt.Printf(" %v %v\n", erstat.Seconds, erstat.State)
							// send the RBF to the flash memory
							Programboard(str[bdid], fg.SetRBF, fg.Debug)
						}

					}
				}

				if fg.Debug == "none" {
					if (fg.SelectMAC != "none") && (fg.SelectMAC == str[bdid].Macaddress) {
						// list all the HPSDR Board information or the select HPSDR Board information

						Listboard(str[bdid])
					} else if fg.SelectMAC == "none" && len(str) > 0 {
						//loop throught the list of discovered HPSDR boards
						for i := 0; i < len(str); i++ {
							Listboard(str[i])
						}
					} else if len(str) == 0 {
						fmt.Printf("      No HPSDR Boards found on interface \"%s\"! \n", *ifn)
					}
				}
			} else {
				fmt.Printf("      Interface not active! \n")
			}
		}
	}
}
