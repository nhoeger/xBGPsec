package server

import "C"
import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type GoSRxProxy struct {
	//client       *RPKIManager
	con                  net.Conn
	conStatus            bool
	ASN                  int
	InputBuffer          []string
	OutputBuffer         []string
	IP                   string
	VerifyNotifyCallback func(*VerifyNotify)
	SyncNotifyCallback   func()
}

// send validation call to SRx-Server
func validate_call(proxy *GoSRxProxy, input string) {
	connection := proxy.con
	bytes2, err := hex.DecodeString(input)
	_, err = connection.Write(bytes2)
	if err != nil {
		log.Fatal(err)
	}

}

// Sends Hello message to SRx-Server
// ASN becomes the identifier of the proxy
func sendHello(proxy GoSRxProxy) {
	hm := HelloMessage{
		PDU:              HelloPDU,
		Version:          "0003",
		reserved:         "00",
		zero:             "00000000",
		length:           "00000014",
		proxy_identifier: "00000001",
		ASN:              "0000" + strconv.FormatInt(int64(proxy.ASN), 16),
	}
	hexString := structToString(hm)
	log.Info(hexString)
	bytes, _ := hex.DecodeString(hexString)
	_, err := proxy.con.Write(bytes)
	if err != nil {
		log.Fatal("Sending Hello Failed: ", err)
	}
}

// New Proxy instance
func createSRxProxy(AS int, ip string, VNC func(*VerifyNotify), SC func()) GoSRxProxy {
	var wg sync.WaitGroup
	wg.Add(1)
	pr := GoSRxProxy{
		ASN:                  AS,
		IP:                   ip,
		VerifyNotifyCallback: VNC,
		SyncNotifyCallback:   SC,
	}
	pr.connectToSrxServer(ip)
	sendHello(pr)
	return pr
}

// Establish a TCP connection with the SRx-Server
// If no IP is provided, the proxy tries to reach localhost:17900
func (proxy *GoSRxProxy) connectToSrxServer(ip string) {
	connectionCounter := 1
	server := "localhost:17900"
	log.Debug("Trying to connect to SRx-Server.")
	log.Debug("SRxServer Address: ", ip)
	if len(ip) != 0 {
		server = ip + ":17900"
	}
	var conn net.Conn
	var err error
	for connectionCounter < 4 {
		connectionCounter += 1
		conn, err = net.Dial("tcp", server)
		if err != nil {
			log.Debug("Connection to Server failed! Trying to connect...")
			time.Sleep(2 * time.Second)
		} else {
			log.Debug("TCP Connection Established")
			proxy.con = conn
			proxy.conStatus = true
			break
		}
	}
	if err != nil {
		log.Fatal("Connection Failed. Please ensure that the SRx-Server is running.")
	}
}

func (proxy *GoSRxProxy) proxyBackgroundThread(wg *sync.WaitGroup) {
	defer wg.Done()
	con := proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info("Lost TCP connection.")
			log.Info(err)
			wg.Add(1)
			proxy.connectToSrxServer(proxy.IP)
			err = nil
			return
		}
		serverResponse := hex.EncodeToString(response[:n])
		wg.Add(1)
		proxy.processInput(serverResponse, wg)
		// log.Debug("Server Input: ", serverResponse)
	}
}

// process messages from the SRx-Server according to their PDU field
func (proxy *GoSRxProxy) processInput(st string, wg *sync.WaitGroup) {
	defer wg.Done()
	PDU := st[:2]
	if PDU == HelloRepsonsePDU {
		log.Debug("Received Hello Response")
		if len(st) > 32 {
			log.Debug("More than just the Hello message")
			wg.Add(1)
			proxy.processInput(st[32:], wg)
		}
	}
	if PDU == SyncMessagePDU {
		log.Debug("Received Sync Request")
		proxy.SyncNotifyCallback()
		if len(st) > 24 {
			wg.Add(1)
			proxy.processInput(st[24:], wg)
		}
	}
	if PDU == VerifyNotifyPDU {
		log.Debug("Processing Validation Input")
		if len(st) > 40 {
			proxy.verifyNotifyCallback(st[:40])
			wg.Add(1)
			proxy.processInput(st[40:], wg)
		} else {
			proxy.verifyNotifyCallback(st)
		}
	}
}

// Convert data structures to string before sending
func structToString(data interface{}) string {
	value := reflect.ValueOf(data)
	numFields := value.NumField()
	returnString := ""
	for i := 0; i < numFields; i++ {
		field := value.Field(i)
		returnString += field.String()
	}
	return returnString
}

// Convert the input string into VerifyNotify
// Parse VerifyNotify to RPKIManager
func (proxy *GoSRxProxy) verifyNotifyCallback(input string) {
	vn := VerifyNotify{
		PDU:              input[:2],
		ResultType:       input[2:4],
		OriginResult:     input[4:6],
		PathResult:       input[6:8],
		ASPAResult:       input[8:10],
		ASConesResult:    input[10:12],
		Zero:             input[12:16],
		Length:           input[16:24],
		RequestToken:     input[24:32],
		UpdateIdentifier: input[32:40],
	}
	proxy.VerifyNotifyCallback(&vn)
}

func (proxy *GoSRxProxy) createV4Request(method SRxVerifyFlag, token int, defRes SRxDefaultResult, prefix IPPrefix, AS32 int, list ASPathList, data *BGPsecData) {
	log.Debug("Creating V4 Request")
	log.Debug("Flags: ", method)
	log.Debug("Token: ", token)
	log.Debug("DefRes: ", defRes)
	log.Debug("Prefix: ", prefix)
	log.Debug("ASN: ", AS32)
	log.Debug("ASList: ", list)
	log.Debug("BGPsecData: ", data)
	tmp := hex.EncodeToString(prefix.address)

	request := VerifyMessage{
		PDU:                  VerifyReqeustIPv4PDU,
		Flags:                fmt.Sprintf("%02X", method),
		OriginResultSource:   fmt.Sprintf("%02X", defRes.resSourceROA),
		PathResultSource:     fmt.Sprintf("%02X", defRes.resSourceBGPsec),
		ASPAResultSource:     fmt.Sprintf("%02X", defRes.resSourceASPA),
		ASConesResultSource:  fmt.Sprintf("%02X", defRes.resSourceASCones),
		ASPathType:           fmt.Sprintf("%02X", list.ASType),
		ASRelationType:       fmt.Sprintf("%02X", list.Relation),
		OriginDefaultResult:  fmt.Sprintf("%02X", defRes.resSourceROA),
		PathDefaultResult:    fmt.Sprintf("%02X", defRes.resSourceBGPsec),
		ASPADefaultResult:    fmt.Sprintf("%02X", defRes.resSourceASPA),
		prefix_len:           fmt.Sprintf("%02X", prefix.length),
		request_token:        fmt.Sprintf("%08X", token) + fmt.Sprintf("%02X", defRes.result.ASConesResult),
		ASConesDefaultResult: "",
		prefix:               tmp[len(tmp)-8:],
		origin_AS:            fmt.Sprintf("%08X", list.ASes[len(list.ASes)-1]),
		local_as:             fmt.Sprintf("%08X", AS32),
	}

	for _, elem := range list.ASes {
		request.as_path_list += fmt.Sprintf("%08X", elem)
	}

	// Check if any BGPsec data were parsed
	// If so: Prepare BGPsec fields of V4 Request
	if data != nil {
		log.Debug("Data not nil")
		request.bgpsec_length = fmt.Sprintf("%08X", data.NumberOfHops*4+data.AttrLength)
		request.num_of_hops = fmt.Sprintf("%04X", data.NumberOfHops)
		request.bgpsec_length = fmt.Sprintf("%04X", data.AttrLength)
		request.afi = fmt.Sprintf("%02X", data.afi)
		request.safi = fmt.Sprintf("%02X", data.safi)
		request.local_as = fmt.Sprintf("%02X", data.localAS)
		request.Length = fmt.Sprintf("%08X", 61+(data.NumberOfHops*4+data.AttrLength))
	} else {
		request.num_of_hops = fmt.Sprintf("%04X", len(list.ASes))
		tmpInt := 4 * len(list.ASes)
		request.length_path_val_data = fmt.Sprintf("%08X", tmpInt)
		request.Length = fmt.Sprintf("%08X", 61+tmpInt)
		request.bgpsec_length = "0000"
		request.afi = "0000"
		request.safi = "00"
		request.prefix_len_bgpsec = "00"
		request.ip_pre_add_byte_a = "00000000"
		request.ip_pre_add_byte_b = "00000000"
		request.ip_pre_add_byte_c = "00000000"
		request.ip_pre_add_byte_d = "00000000"
	}

	log.Debug("Proxy Message: ")
	printValReq(request)
	validate_call(*&proxy, structToString(request))
}

func (proxy *GoSRxProxy) verifyUpdate(localID int, ROA bool, BGPsec bool, ASPA bool, ASCones bool, result SRxDefaultResult, prefix IPPrefix, AS int, data *BGPsecData, list ASPathList) {
	if !proxy.conStatus {
		log.Fatal("Abort verify, not connected to SRx server!")
		return
	}

	var method SRxVerifyFlag = 0

	if ROA {
		method |= SRX_FLAG_ROA
	}
	if BGPsec {
		method |= SRX_FLAG_BGPSEC
	}
	if ASPA {
		method |= SRX_FLAG_ASPA
	}
	if ASCones {
		method |= SRX_FLAG_ASCONE
	}
	if localID != 0 {
		method |= SRX_FLAG_REQUEST_RECEIPT
	}

	isV4 := prefix.version == 4
	if isV4 {
		log.Debug("Debug: verifyUpdate - prefix->addr: ", prefix.address)
	}

	if isV4 {
		log.Debug("Debug: ASCONE - verifyUpdate - createV4Request")
		proxy.createV4Request(method, localID, result, prefix, AS, list, data)
	} else {
		log.Debug("Debug: ASCONE - verifyUpdate - createV6Request")
	}

}

func (proxy *GoSRxProxy) validateBGPsec(e *fsmMsg, vm *VerifyMessage) {
	log.Debug("Starting with the following VerifyMessage: ", vm)
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)

	var nlri_processed bool
	var prefix_addr net.IP
	var prefix_len uint8
	var nlri_afi uint16
	var nlri_safi uint8

	// find the position of bgpsec attribute
	//
	data := e.payload
	data = data[bgp.BGP_HEADER_LENGTH:]
	if update.WithdrawnRoutesLen > 0 {
		data = data[2+update.WithdrawnRoutesLen:]
	} else {
		data = data[2:]
	}

	data = data[2:]
	for pathlen := update.TotalPathAttributeLen; pathlen > 0; {
		p, _ := bgp.GetPathAttribute(data)
		p.DecodeFromBytes(data)

		pathlen -= uint16(p.Len())

		if bgp.BGPAttrType(data[1]) != bgp.BGP_ATTR_TYPE_BGPSEC {
			data = data[p.Len():]
		} else {
			break
		}
	}

	//
	// find nlri attribute first and extract prefix info for bgpsec validation
	//
	for _, path := range e.PathList {

		// find MP NLRI attribute first
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI) {
				log.Debug("received MP NLRI: %#v", path)
				prefix_addr = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Prefix
				prefix_len = p.(*bgp.PathAttributeMpReachNLRI).Value[0].(*bgp.IPAddrPrefix).Length
				nlri_afi = p.(*bgp.PathAttributeMpReachNLRI).AFI
				nlri_safi = p.(*bgp.PathAttributeMpReachNLRI).SAFI

				log.WithFields(log.Fields{"Topic": "Bgpsec"}).Debug("prefix:", prefix_addr, prefix_len, nlri_afi, nlri_safi)
				nlri_processed = true
				log.Debug("received MP NLRI: %#v", nlri_processed)
			}
		}

		// find the BGPSec atttribute
		for _, p := range path.GetPathAttrs() {
			typ := uint(p.GetType())
			if typ == uint(bgp.BGP_ATTR_TYPE_BGPSEC) && nlri_processed {
				log.Debug("BGPsec validation start ")

				/*myas  := proxy.ASN
				big2 := make([]byte, 4, 4)
				for i := 0; i < 4; i++ {
					u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&myas)) + uintptr(i)))
					big2 = append(big2, u8)
				}*/

				/*valData := C.SCA_BGPSecValidationData{
					myAS:             C.uint(binary.BigEndian.Uint32(big2[4:8])),
					status:           C.sca_status_t(0),
					bgpsec_path_attr: nil,
					nlri:             nil,
					hashMessage:      [2](*C.SCA_HashMessage){},
				}*/

				var bsPathAttrLength int
				Flags := bgp.BGPAttrFlag(data[0])
				if Flags&bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
					bsPathAttrLength = int(binary.BigEndian.Uint16(data[2:4]))
				} else {
					bsPathAttrLength = int(uint16(data[2]))
				}

				bsPathAttrLength = bsPathAttrLength + 4 // flag(1) + length(1) + its own length octet (2)
				data = data[:bsPathAttrLength]

				//bsPathAttr := data

				/*binary.Write(buf, binary.BigEndian, bsPathAttr)
				bl := buf.Len()
				o := (*[1 << 20]C.uchar)(pa)

				for i := 0; i < bl; i++ {
					b, _ := buf.ReadByte()
					o[i] = C.uchar(b)
				}
				valData.bgpsec_path_attr = (*C.uchar)(pa)*/

				// prefix handling
				//
				//prefix2 := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
				//defer C.free(unsafe.Pointer(prefix2))
				/*px := &Go_SCA_Prefix{
					Afi:    nlri_afi,
					Safi:   nlri_safi,
					Length: prefix_len,
					Addr:   [16]byte{},
				}*/

				/*pxip := prefix_addr
				copy(px.Addr[:], pxip)
				px.Pack(unsafe.Pointer(prefix2))
				/* comment out for performance measurement
				C.PrintSCA_Prefix(*prefix2)
				*/
				//log.Debug("prefix2 : %#v", prefix2)

				/*valData.nlri = prefix2
				log.Debug("valData : %#v", valData)
				log.Debug("valData.bgpsec_path_attr : %#v", valData.bgpsec_path_attr)
				/* comment out for performance measurement
				C.printHex(C.int(bs_path_attr_length), valData.bgpsec_path_attr)
				*/
				//log.Debug("valData.nlri : %#v", *valData.nlri)

				//bm.bgpsecValData = valData
				// call validate
				//ret := C.validate(&valData)

			} // end of if - bgpsec validation process
		} // end of if, get path attr
	} // end of if - path list

	//vm.afi = nlri_afi
	log.Debug("Ending with the following VerifyMessage: ", vm)
}
