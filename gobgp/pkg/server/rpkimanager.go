package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type RPKIManager struct {
	AS            int
	Proxy         *GoSRxProxy
	StartTime     time.Time
	Ready         *bool
	Server        *BgpServer
	SKI           string
	CurrentUpdate int
	PendingUpdate []*SRxTuple
}

type SRxTuple struct {
	local_id     int
	srx_id       string
	peer         *peer
	path         *table.Path
	notification *bgp.BGPMessage
	stayIdle     bool
	fsmMsg       *fsmMsg
	bgpMsg       *bgp.BGPMessage
	origin       bool
	aspa         bool
	std_val      bool
	sig_val      bool
	otc          string
	prefixAddr   net.IP
	prefixLen    int
	ASPathList   []int
	OriginAS     int
	signatures   []string
	timestamp    uint32
}

// NewRPKIManager Create new RPKI manager instance
// Input: pointer to BGPServer
func NewRPKIManager(s *BgpServer) (*RPKIManager, error) {
	// s.logger.Info("[i] Creating new RPKI Manager", nil)
	// ASN := int(s.bgpConfig.Global.Config.As)
	ASN := 65000
	rm := &RPKIManager{
		AS:            ASN,
		Server:        s,
		StartTime:     time.Now(),
		Ready:         new(bool),
		Proxy:         nil,
		SKI:           "",
		CurrentUpdate: 1,
	}
	*rm.Ready = true
	return rm, nil
}

// SetSRxServer Parses the IP address of the SRx-Server
// Proxy can establish a connection with the SRx-Server and sends a hello message
// Thread mandatory to keep proxy alive during runtime
func (rm *RPKIManager) SetSRxServer(ip string) error {
	rm.Proxy, _ = NewGoSRxProxy(rm.AS, ip, rm.SKI, nil, nil, rm)
	return nil
}

// SetSKI sets the SKI of the RPKIManager
func (rm *RPKIManager) SetSKI(SKI string) error {
	fmt.Println("Setting SKI", SKI)
	if len(SKI) != 40 {
		fmt.Println("SKI is not 40 characters long")
		return nil
	}
	rm.SKI = SKI
	return nil
}

func (rm *RPKIManager) SetAS(as uint32) error {
	if rm.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	rm.AS = int(as)
	return nil
}

// Generate signatures
func (rm *RPKIManager) GenerateSignature(peer *peer, paths []*table.Path, notification *bgp.BGPMessage, stayIdle bool) {
	// Prepare everything for signature generation for each path
	// Iterate over all paths
	for _, path := range paths {
		// Extract prefix
		prefixLen := 0
		prefixAddr := net.ParseIP("0.0.0.0")
		pathString := path.String()
		words := strings.Fields(pathString)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmpPref, _ := strconv.Atoi(word[j+1:])
					prefixLen = tmpPref
					prefixAddr = net.ParseIP(word[:j])
				}
			}
		}

		prefix_length := prefixLen
		prefix_address := prefixAddr

		// Extract AS path
		asList := path.GetAsList()
		// Convert AS path to a list of integers
		var array []int
		for _, asn := range asList {
			array = append(array, int(asn))
		}

		fmt.Printf("AS Path: %v\n", asList)
		// Generate timestamp
		timestamp := uint32(time.Now().Unix())

		// TODO: Add OTC functionality
		otcField := fmt.Sprintf("%08x", int64(65000))

		// Generate identifier
		identifier := fmt.Sprintf("%08x", int64(rm.CurrentUpdate))

		// Store the SRxTuple
		update := SRxTuple{
			local_id:     rm.CurrentUpdate,
			srx_id:       identifier,
			peer:         peer,
			path:         path,
			notification: notification,
			stayIdle:     stayIdle,
			timestamp:    timestamp,
			otc:          otcField,
			ASPathList:   array,
			prefixAddr:   prefix_address,
			prefixLen:    prefix_length,
		}
		rm.PendingUpdate = append(rm.PendingUpdate, &update)
		rm.CurrentUpdate = (rm.CurrentUpdate % 10000) + 1

		// Parse request to proxy
		rm.Proxy.sendSigtraGenerationRequest(update)
	}
}

// Callback function to handle generated signatures
// This function is called by the GoSRxProxy when a signature is recevied from the SRx-Server
// It extracts the signature identifier from the input string and finds the corresponding update in PendingUpdate
// It creates a new SigtraBlock and appends it to the PathAttributeSignature of the update's path
func (rm *RPKIManager) HandleGeneratedSignature(input string) {
	fmt.Println("[i] Handling generated signature:", input)

	// First find update
	signatureIdentifier := input[24:32]
	// Extract signature identifier from hex value
	signatureIdentifierInt, _ := strconv.ParseUint(signatureIdentifier, 16, 32)
	sigID := int(signatureIdentifierInt) // Multiply by 2 to account for hex representation
	fmt.Printf("Signature Identifier: %d\n", sigID)

	for _, update := range rm.PendingUpdate {
		if update.local_id == sigID {
			fmt.Printf("Found matching update for signature identifier: %d\n", sigID)

			// Calculate passed time
			t := time.Unix(int64(update.timestamp), 0)

			passedTime := time.Since(t).Seconds()
			fmt.Printf("Passed time since update: %.2f seconds\n", passedTime)

			signatureLength := input[32:40]

			// Extract acutal length form hex value
			lengthValue, _ := strconv.ParseUint(signatureLength, 16, 32)
			lengthValue *= 2

			signature := input[40:lengthValue]

			// print all fields
			fmt.Printf("Signature Identifier: %d\n", sigID)
			fmt.Printf("Signature Length: %s\n", signatureLength)
			fmt.Printf("Signature Length Value: %d\n", lengthValue)
			fmt.Printf("Signature: %s\n", signature)

			// Create a new SigtraBlock
			sigtraBlock := bgp.SigtraBlock{
				Signature:  [72]byte{},
				Timestamp:  update.timestamp,
				SKI:        [20]byte{},
				CreatingAS: uint32(rm.AS),
				NextASN:    uint32(update.peer.AS()),
			}

			// Fill in the Signature field
			/*signatureBytes := []byte(signature)
			sigtraBlock.Signature = [72]byte{}
			copy(sigtraBlock.Signature[:], signatureBytes)*/
			signatureBytes, err := hex.DecodeString(signature)
			if err != nil {
				fmt.Println("Error decoding signature:", err)
				return
			}
			sigtraBlock.SignatureLength = uint32(len(signatureBytes))
			copy(sigtraBlock.Signature[:], signatureBytes)

			// Fill in the SKI field
			skiBytes, err := hex.DecodeString(rm.SKI)
			if err != nil {
				fmt.Println("Error decoding SKI:", err)
			}
			if len(skiBytes) != 20 {
				fmt.Println("SKI must be 20 bytes long")
				return
			}
			copy(sigtraBlock.SKI[:], skiBytes)

			working_path := update.path
			attrs := working_path.GetPathAttrs()
			var sigAttr *bgp.PathAttributeSignature

			// Search for existing PathAttributeSignature
			for _, attr := range attrs {
				if attr.GetType() == bgp.BGP_ATTR_TYPE_SIGNATURE {
					// Type assertion to *PathAttributeSignature
					if s, ok := attr.(*bgp.PathAttributeSignature); ok {
						sigAttr = s
						break
					}
				}
			}

			if sigAttr != nil {
				// Attribute exists, append block
				sigAttr.Blocks = append(sigAttr.Blocks, sigtraBlock)
			} else {
				// No Signature attribute present, create new one
				sigAttr = bgp.NewPathAttributeSignature([]bgp.SigtraBlock{sigtraBlock})
			}
			// Print all fields of the signature attribute
			fmt.Printf("Signature Attribute:\n")
			fmt.Printf("  Signature Identifier: %d\n", sigID)
			fmt.Printf("  Signature Length: %s\n", signatureLength)
			fmt.Printf("  Signature Length Value: %d\n", lengthValue)
			fmt.Printf("  Number of Blocks: %d\n", len(sigAttr.Blocks))
			for i := range sigAttr.Blocks {
				fmt.Printf("  Block %d:\n", i+1)
				// Convert signature bytes to hex for printing
				sigHex := hex.EncodeToString(sigAttr.Blocks[i].Signature[:])
				fmt.Printf("    Signature Length: %d\n", len(sigAttr.Blocks[i].Signature))
				fmt.Printf("    Signature (hex): %s\n", sigHex)
				fmt.Printf("    Signature: %s\n", sigAttr.Blocks[i].Signature)
				fmt.Printf("    Timestamp: %d\n", sigAttr.Blocks[i].Timestamp)
				fmt.Printf("    SKI: %x\n", sigAttr.Blocks[i].SKI)
				fmt.Printf("    Creating AS: %d\n", sigAttr.Blocks[i].CreatingAS)
				fmt.Printf("    Next ASN: %d\n", sigAttr.Blocks[i].NextASN)
			}

			// Setze die Attribute wieder zurück ins Path-Objekt (je nach API)
			working_path.SetSignatureAttribute(sigAttr)

			// Convert update path from *table.Path to []*table.Path
			paths := []*table.Path{update.path}
			rm.Server.sendfsmOutgoingMsgWithSig(update.peer, paths, update.notification, update.stayIdle)
			return
		}
	}
	fmt.Println("[!] No matching update found for signature identifier:", sigID)
}

func (rm *RPKIManager) validate(peer *peer, m *bgp.BGPMessage, e *fsmMsg) {
	fmt.Println("[i] Validating BGP update message")
	// Iterate over all paths in the update message
	for _, path := range e.PathList {
		// Create a new SRxTuple for each path
		update := SRxTuple{
			local_id: rm.CurrentUpdate,
			srx_id:   "",
			peer:     peer,
			fsmMsg:   e,
			bgpMsg:   m,
			origin:   !rm.Server.bgpConfig.Global.Config.ROA,
			aspa:     !rm.Server.bgpConfig.Global.Config.ASPA,
			OriginAS: int(peer.AS()),
		}
		var flag SRxVerifyFlag
		var reqRes SRxDefaultResult
		var prefix IPPrefix
		//var ASN int
		var ASlist ASPathList

		flag = 128
		if update.origin {
			flag += 1
		}
		if update.aspa {
			flag += 4
		}

		reqRes.resSourceBGPsec = SRxRSUnknown
		reqRes.resSourceROA = SRxRSUnknown
		reqRes.resSourceASPA = SRxRSUnknown
		srxRes := SRxResult{
			ROAResult:    3,
			BGPsecResult: 3,
			ASPAResult:   3,
		}
		reqRes.result = srxRes

		prefixLen := 0
		prefixAddr := net.ParseIP("0.0.0.0")
		pathString := path.String()
		words := strings.Fields(pathString)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmpPref, _ := strconv.Atoi(word[j+1:])
					prefixLen = tmpPref
					prefixAddr = net.ParseIP(word[:j])
				}
			}
		}

		prefix.length = prefixLen
		prefix.version = 4
		prefix.address = prefixAddr
		update.prefixAddr = prefixAddr
		update.prefixLen = prefixLen

		var array []int
		asList := path.GetAsList()
		fmt.Println("ASlist we have from path:", asList)
		for i, asn := range asList {
			ASlist.length = i
			ASlist.ASes = append(array, int(asn))
			ASlist.ASType = ASSequence
			ASlist.Relation = unknown
		}

		asIntList := make([]int, len(asList))
		for i, asn := range asList {
			asIntList[i] = int(asn)
		}

		update.ASPathList = asIntList
		rm.PendingUpdate = append(rm.PendingUpdate, &update)
		rm.CurrentUpdate = (rm.CurrentUpdate % 10000) + 1

		// prepare signature generation request if there are any signatures present
		attrs := path.GetPathAttrs()
		for _, attr := range attrs {
			if attr.GetType() == bgp.BGP_ATTR_TYPE_SIGNATURE {
				if sigAttr, ok := attr.(*bgp.PathAttributeSignature); ok {
					// Print block count and details
					numberOfBlocks := len(sigAttr.Blocks)
					fmt.Printf("Found %d signature blocks in PathAttributeSignature\n", numberOfBlocks)
					if numberOfBlocks > 0 {
						// Parse data to proxy to send a validation request
						rm.Proxy.sendSigtraValidationRequest(sigAttr.Blocks, &update)
					}
				}
			}
		}

		// rm.Proxy.validate(&update)
	}
}
