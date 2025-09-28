package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

/*
 * GoSRxProxy is a struct that represents a connection to the SRx server.
 * It contains the connection object, ASN, identifier, input and output buffers,
 * IP address, SKI, and callback functions for verification and synchronization.
 * Setup function:
 */

type GoSRxProxy struct {
	con              net.Conn
	conStatus        bool
	ASN              int
	identifier       string
	InputBuffer      []string
	OutputBuffer     []string
	IP               string
	SKI              string
	onVerify         func(string)
	onSync           func()
	UpdateIdentifier int
	RPKIManager      *RPKIManager
}

func NewGoSRxProxy(asn int, ip, ski string, onVerify func(string), onSync func(), rpkimanager *RPKIManager) (*GoSRxProxy, error) {
	p := &GoSRxProxy{
		ASN:              asn,
		IP:               ip,
		SKI:              ski,
		InputBuffer:      make([]string, 0),
		OutputBuffer:     make([]string, 0),
		onVerify:         onVerify,
		onSync:           onSync,
		UpdateIdentifier: 1,
		RPKIManager:      rpkimanager,
	}

	if !p.connectToSRxServer(ip) {
		return nil, fmt.Errorf("failed to connect to SRx server")
	}

	return p, nil
}

func (p *GoSRxProxy) connectToSRxServer(ip string) bool {
	fmt.Println("[i] Connecting to SRx server at", ip)
	server := ip + ":17900"
	for {
		conn, err := net.Dial("tcp", server)
		if err == nil {
			p.con = conn
			p.conStatus = true
			fmt.Println("[i] Connected to SRx server:", server)
			p.sendHello()
			var wg sync.WaitGroup
			wg.Add(1)
			go p.ProxyBackgroundThread(&wg)
			return true
		}
	}
}

func (p *GoSRxProxy) sendHello() bool {
	fmt.Println("[i] Sending Hello message to SRx server...")
	hello := HelloMessage{
		PDU:      fmt.Sprintf("%02x", PDU_SRXPROXY_HELLO),
		Version:  "0003",
		reserved: "00",
		zero:     "00000000",
		length:   "00000000",
		ASN:      fmt.Sprintf("%08x", int64(p.ASN)),
		SKI:      p.SKI,
	}
	// Generate a unique identifier for the proxy
	hello.proxy_identifier = fmt.Sprintf("%08x", time.Now().UnixNano())

	length := len(hello.PDU+hello.Version+hello.reserved+hello.zero+hello.length+hello.proxy_identifier+hello.ASN+hello.SKI) / 2
	hello.length = fmt.Sprintf("%08x", length)

	hexString := structToString(hello)
	bytes, _ := hex.DecodeString(hexString)
	_, err := p.con.Write(bytes)
	if err != nil {
		fmt.Println("[!] Failed to send Hello message:", err)
		return false
	}
	return true
}

func (proxy *GoSRxProxy) ProxyBackgroundThread(wg *sync.WaitGroup) bool {
	defer wg.Done()
	con := proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			fmt.Println("Lost TCP connection.")
			fmt.Println(err)
			wg.Add(1)
			proxy.connectToSRxServer(proxy.IP)
			err = nil
			return false
		}
		serverResponse := hex.EncodeToString(response[:n])
		wg.Add(1)
		proxy.processInput(serverResponse, wg)
	}
}

/*
 * processInput is a function that processes the input from the SRx server.
 * It parses the PDU and calls the appropriate handler function based on the PDU type.
 * It also handles the case where the input is split into multiple packets.
 */

func (proxy *GoSRxProxy) processInput(st string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("[i] Processing input from SRx server:", st)
	packet_PDU := st[0:2]
	pdu, _ := strconv.ParseInt(packet_PDU, 16, 0)
	received_packet_length := int64(len(st) / 2)
	internal_packet_length, _ := strconv.ParseInt(st[16:24], 16, 0)
	to_process := st[0 : internal_packet_length*2]
	fmt.Println("[i] Received PDU:", packet_PDU, "Length:", received_packet_length, "Internal Length:", internal_packet_length)
	switch pdu {
	case PDU_SRXPROXY_HELLO_RESPONSE:
		fmt.Println("[i] Received PDU_SRXPROXY_HELLO_RESPONSE")
		proxy.handleHelloResponse(to_process)
	case PDU_SRXPROXY_SYNC_REQUEST:
		fmt.Println("[i] Received PDU_SRXPROXY_SYNC_REQUEST")
	case PDU_SRXPROXY_ERROR:
		fmt.Println("[!] Received PDU_SRXPROXY_ERROR")
	case PDU_SRXPROXY_VERI_NOTIFICATION:
		fmt.Println("[i] Received PDU_SRXPROXY_VERI_NOTIFICATION")
	case PDU_SRXPROXY_GOODBYE:
		fmt.Println("[i] Received PDU_SRXPROXY_GOODBYE")
	case PDU_SRXPROXY_SIGN_NOTIFICATION:
		fmt.Println("[i] Received PDU_SRXPROXY_SIGN_NOTIFICATION")
	case PDU_SRXPROXY_SIGTRA_SIGNATURE_RESPONSE:
		fmt.Println("[i] Received SigTra Signature Response")
		proxy.RPKIManager.HandleGeneratedSignature(to_process)
	case PDU_SRXPROXY_SIGTRA_VALIDATION_RESPONSE:
		fmt.Println("[i] Received SigTra Validation Response")
		fmt.Println("[i] SigTra Validation Response: ", st)
	default:
		fmt.Println("[!] Unknown PDU:", packet_PDU)
	}

	if received_packet_length > internal_packet_length {
		fmt.Println("[i] Received packet length is greater than internal packet length")
		next_packet := st[internal_packet_length*2:]
		wg.Add(1)
		proxy.processInput(next_packet, wg)
	}
}

func (proxy *GoSRxProxy) handleHelloResponse(st string) {
	hmsg := HelloResponseMessage{
		PDU:              st[0:2],
		version:          st[2:6],
		reserved:         st[6:8],
		zero:             st[8:16],
		length:           st[16:24],
		proxy_identifier: st[24:32],
	}
	proxy.identifier = hmsg.proxy_identifier
}

/*
 * Update validation and signature gerneration
 */
func buildSigtraBlock(id int, block bgp.SigtraBlock) SigBlock {
	// Signature auffüllen
	sigBytes := block.Signature[:block.SignatureLength]
	var sigFilled [72]byte
	copy(sigFilled[:], sigBytes)

	// SKI auffüllen (falls nötig, meist schon [20]byte)
	var skiFilled [20]byte
	copy(skiFilled[:], block.SKI[:])

	fmt.Println("SigLen:", block.SignatureLength)

	sigBlock := SigBlock{
		id:              fmt.Sprintf("%02x", id),
		signatureLength: fmt.Sprintf("%08x", block.SignatureLength),
		signature:       hex.EncodeToString(sigFilled[:]), // immer 72 Bytes als Hex
		timestamp:       fmt.Sprintf("%08x", block.Timestamp),
		ski:             hex.EncodeToString(skiFilled[:]), // immer 20 Bytes als Hex
		creatingAS:      fmt.Sprintf("%08x", block.CreatingAS),
		nextAS:          fmt.Sprintf("%08x", block.NextASN),
	}
	// pirnt block human readable
	//fmt.Println("[i] Sigtra Block ID:", sigBlock.id)
	//fmt.Println("[i] Signature Length:", sigBlock.signatureLength)
	//fmt.Println("[i] Signature:", sigBlock.signature)
	//fmt.Println("[i] Timestamp:", sigBlock.timestamp)
	//fmt.Println("[i] SKI:", sigBlock.ski)
	//fmt.Println("[i] Creating AS:", sigBlock.creatingAS)
	//fmt.Println("[i] Next AS:", sigBlock.nextAS)
	// print the struct as a string for debugging
	//fmt.Println("[i] structToString(sigBlock): ", structToString(sigBlock))
	return sigBlock
}

func (proxy *GoSRxProxy) sendSigtraValidationRequest(blocks []bgp.SigtraBlock, update *SRxTuple) {
	fmt.Println("[i] Sending SigTra Validation Request to SRx server")
	// SRx Basic Header
	hdr := SRxHeader{
		PDU:        fmt.Sprintf("%02x", PDU_SRXPROXY_SIGTRA_VALIDATION_REQUEST),
		Reserved16: "0000",
		Reserved8:  "00",
		Reserved32: "00000000",
		Length:     "00000000",
	}

	vr := SigTraValReq{}
	current_block := 0

	// print the prefix for debugging
	tmp := hex.EncodeToString(update.prefixAddr)
	tmpPrefix := tmp[len(tmp)-8:]

	vr.signatureID = fmt.Sprintf("%08x", int64(update.local_id))
	vr.blockCount = fmt.Sprintf("%02x", len(blocks))
	vr.prefixLen = fmt.Sprintf("%02x", update.prefixLen)
	vr.prefix = tmpPrefix

	vr.asPathLen = fmt.Sprintf("%02x", len(update.ASPathList))
	for _, asn := range update.ASPathList {
		// Convert ASN to hex and pad it to 8 characters
		hexValue := fmt.Sprintf("%08x", asn)
		vr.asPath += hexValue
	}

	// fill in the rest of the AS path with 0
	length := len(update.ASPathList)
	for i := length; i < 16; i++ {
		vr.asPath += "00000000"
	}

	vr.otcField = fmt.Sprintf("%08x", update.otc)
	vr.blocks = ""
	vr.blockCount = fmt.Sprintf("%02x", len(blocks))

	for _, block := range blocks {
		sigBlock := buildSigtraBlock(current_block+1, block)
		vr.blocks += sigBlock.id + sigBlock.signatureLength + sigBlock.signature + sigBlock.timestamp + sigBlock.ski + sigBlock.creatingAS + sigBlock.nextAS
		current_block++
	}

	hdr_length := len(hdr.PDU) + len(hdr.Reserved16) + len(hdr.Reserved8) + len(hdr.Reserved32) + len(hdr.Length)
	vr_length := len(vr.signatureID) + len(vr.blockCount) + len(vr.prefixLen) + len(vr.prefix) + len(vr.asPathLen) + len(vr.asPath) + len(vr.otcField) + len(vr.blocks)
	total_length := hdr_length + vr_length
	total_length = total_length / 2
	hdr.Length = fmt.Sprintf("%08x", total_length)

	fmt.Println("[i] structToString(vr): ", structToString(vr))
	header, _ := hex.DecodeString(structToString(hdr))
	body, _ := hex.DecodeString(structToString(vr))

	bytes := make([]byte, len(header)+len(body))
	copy(bytes, header)
	// dump bytes

	copy(bytes[len(header):], body)
	fmt.Println("[i] Bytes to send: ", hex.EncodeToString(bytes))
	_, err := proxy.con.Write(bytes)
	if err != nil {
		fmt.Println("[i] Sending SRXPROXY_SIGTRA__VALIDATION_REQUEST Failed: ", err)
	}
}

// This function sends a SigTraGenRequest to the SRx-Server
// It is used to request the generation of a signature for a given prefix
// and a given number of peers
func (proxy *GoSRxProxy) sendSigtraGenerationRequest(s SRxTuple) {
	// SRx Basic Header
	hdr := proxy.generateHeader(PDU_SRXPROXY_SIGTRA_GENERATION_REQUEST)
	fmt.Println("Received the follwoing AS Patjh List: ", s.ASPathList)
	// Packet to request signature generation
	sr := SigTraGenRequest{}
	sr.requestingAS = fmt.Sprintf("%08x", int64(proxy.ASN))
	sr.SignatureID = fmt.Sprintf("%08x", int64(s.local_id))
	sr.ASPathLength = fmt.Sprintf("%02x", len(s.ASPathList))
	fmt.Println("AS Path Length: ", sr.ASPathLength)

	// Prefix
	tmp := hex.EncodeToString(s.prefixAddr)
	sr.Prefix = tmp[len(tmp)-8:]
	sr.PrefixLength = strconv.FormatInt(int64(s.prefixLen), 16)

	for _, asn := range s.ASPathList {
		// Convert ASN to hex and pad it to 8 characters
		hexValue := fmt.Sprintf("%08x", asn)
		sr.ASPath += hexValue
	}

	// fill in the rest of the AS path with 0
	length := len(s.ASPathList)
	for i := length; i < 16; i++ {
		sr.ASPath += "00000000"
	}

	sr.Timestamp = fmt.Sprintf("%08x", int64(time.Now().Unix()))
	sr.OTCField = s.otc
	// Peers: Currently always one peer
	numberOfPeers := 1
	sr.PeerListLength = fmt.Sprintf("%02x", numberOfPeers)
	sr.PeerList = fmt.Sprintf("%08x", int64(s.peer.AS()))
	// fill in the rest of the AS path with 0
	for i := numberOfPeers; i < 16; i++ {
		sr.PeerList += "00000000"
	}

	sr.OriginAS = fmt.Sprintf("%08x", s.ASPathList[length-1])

	// TODO: Implement block count
	sr.blockCount = "00"
	hdr_length := len(hdr.PDU) + len(hdr.Reserved16) + len(hdr.Reserved8) + len(hdr.Reserved32) + len(hdr.Length)
	sr_length := len(sr.SignatureID) + len(sr.PrefixLength) + len(sr.Prefix) +
		len(sr.ASPathLength) + len(sr.ASPath) + len(sr.OriginAS) + len(sr.Timestamp) +
		len(sr.OTCField) + len(sr.PeerListLength) + len(sr.PeerList) + len(sr.requestingAS) + len(sr.blockCount)

	total_length := hdr_length + sr_length
	total_length = total_length / 2
	hdr.Length = fmt.Sprintf("%08x", total_length)
	hexString_hdr := structToString(hdr)
	hexString_sr := structToString(sr)
	bytes_sr, _ := hex.DecodeString(hexString_sr)
	bytes_hdr, _ := hex.DecodeString(hexString_hdr)
	bytes := make([]byte, len(bytes_hdr)+len(bytes_sr))
	fmt.Println("Hex String: ", hexString_sr, " length; ", len(hexString_sr))
	fmt.Println("Hex String: ", hexString_hdr, " length; ", len(hexString_hdr))
	copy(bytes, bytes_hdr)
	copy(bytes[len(bytes_hdr):], bytes_sr)
	_, err := proxy.con.Write(bytes)
	if err != nil {
		fmt.Println("[i] Sending SRXPROXY_SIGTRA_GENERATION_REQUEST Failed: ", err)
	}
}

// Send a test verification request to the srx-server
// Create a Validation message for an incoming BGP UPDATE message
// inputs: BGP peer, the message and message data
func (proxy *GoSRxProxy) validate(update *SRxTuple) {
	id := 1

	// Create new message for each path
	vm := VerifyMessage{
		PDU:                  "03",
		OriginResultSource:   "01",
		PathResultSource:     "01",
		ASPAResultSource:     "01",
		reserved:             "01",
		ASPathType:           "02",
		ASRelationType:       "04",
		Length:               "00000044",
		OriginDefaultResult:  "03",
		PathDefaultResult:    "03",
		ASPADefaultResult:    "03",
		prefix_len:           "18",
		request_token:        fmt.Sprintf("%08X", id) + "03",
		prefix:               "00000000",
		origin_AS:            "0000fdec",
		length_path_val_data: "00000000",
		bgpsec_length:        "0000",
		afi:                  "0000",
		num_of_hops:          "0000",
		safi:                 "00",
		prefix_len_bgpsec:    "00",
		ip_pre_add_byte_a:    "00000000",
		ip_pre_add_byte_b:    "00000000",
		ip_pre_add_byte_c:    "00000000",
		ip_pre_add_byte_d:    "00000000",
		local_as:             "00000000",
		as_path_list:         "",
		bgpsec:               "",
	}

	// request flag for ASPA validation
	tmpFlag := 128

	// 1 ROA
	// 2 BGPsec
	// 4 Transitive
	// 8 ASPA
	tmpFlag += 4
	vm.Flags = fmt.Sprintf("%02X", tmpFlag)

	// fake as_path
	asList := [4]string{"65000", "65001", "65002", "65003"}
	for _, asn := range asList {
		hexValue := fmt.Sprintf("%08X", asn)
		vm.as_path_list += hexValue

	}

	// fake prefix
	prefixLen := 16
	prefixAddr := net.ParseIP("15.64.5.0")

	tmp := hex.EncodeToString(prefixAddr)
	vm.prefix = tmp[len(tmp)-8:]
	vm.prefix_len = strconv.FormatInt(int64(prefixLen), 16)
	vm.origin_AS = fmt.Sprintf("%08X", asList[len(asList)-1])

	vm.num_of_hops = fmt.Sprintf("%04X", len(asList))
	tmpInt := 4 * len(asList)
	vm.Length = fmt.Sprintf("%08X", 61+tmpInt)
	vm.length_path_val_data = fmt.Sprintf("%08X", tmpInt)
	vm.origin_AS = fmt.Sprintf("%08X", 65000)
	vm.local_as = fmt.Sprintf("%08X", 65002)

	request_as_string := structToString(vm)
	// printValReq(vm)
	validate_call(proxy, request_as_string)
}

func validate_call(proxy *GoSRxProxy, input string) {
	fmt.Println("Sending Validate Request")
	connection := proxy.con
	bytes2, err := hex.DecodeString(input)
	_, err = connection.Write(bytes2)
	if err != nil {
		fmt.Println(err)
	}

}

func (proxy *GoSRxProxy) generateHeader(PDU int) SRxHeader {
	hdr := SRxHeader{
		PDU:        fmt.Sprintf("%02x", PDU),
		Reserved16: "0000",
		Reserved8:  "00",
		Reserved32: "00000000",
		Length:     "00000000",
	}
	return hdr
}
