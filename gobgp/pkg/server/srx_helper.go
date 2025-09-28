package server

import (
	"fmt"
	"reflect"
)

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

func printSigtraGenReq(sg SigTraGenRequest) {
	fmt.Println("+----------------------------------+")
	fmt.Println("SignatureID:           ", sg.SignatureID)
	fmt.Println("PrefixLength:          ", sg.PrefixLength)
	fmt.Println("Prefix:                ", sg.Prefix)
	fmt.Println("ASPathLength:          ", sg.ASPathLength)
	fmt.Println("ASPath:                ", sg.ASPath)
	fmt.Println("Timestamp:             ", sg.Timestamp)
	fmt.Println("OTCField:              ", sg.OTCField)
	fmt.Println("PeerListLength:        ", sg.PeerListLength)
	fmt.Println("PeerList:              ", sg.PeerList)
	fmt.Println("+----------------------------------+")
}

func printHeader(hdr SRxHeader) {
	fmt.Println("+----------------------------------+")
	fmt.Println("PDU:                   ", hdr.PDU)
	fmt.Println("Reserved16:            ", hdr.Reserved16)
	fmt.Println("Reserved8:             ", hdr.Reserved8)
	fmt.Println("Reserved32:            ", hdr.Reserved32)
	fmt.Println("Length:                ", hdr.Length)
	fmt.Println("+----------------------------------+")
}

func printValReq(vm VerifyMessage) {
	fmt.Println("+----------------------------------+")
	fmt.Println("PDU:                   ", vm.PDU)
	fmt.Println("Flags:                 ", vm.Flags)
	fmt.Println("OriginResultSoruce:    ", vm.OriginResultSource)
	fmt.Println("PathResultSoruce:      ", vm.PathResultSource)
	fmt.Println("ASPAResultSoruce:      ", vm.ASPAResultSource)
	fmt.Println("ASConesResultSoruce:   ", vm.ASConesResultSource)
	fmt.Println("reserved:              ", vm.reserved)
	fmt.Println("ASPathType:            ", vm.ASPathType)
	fmt.Println("ASRelationType:        ", vm.ASRelationType)
	fmt.Println("Length:                ", vm.Length)
	fmt.Println("OriginDefaultResult:   ", vm.OriginDefaultResult)
	fmt.Println("PathDefaultResult:     ", vm.PathDefaultResult)
	fmt.Println("ASPADefaultResult:     ", vm.ASPADefaultResult)
	fmt.Println("ASConesDefaultResult:  ", vm.ASConesDefaultResult)
	fmt.Println("prefix_len:            ", vm.prefix_len)
	fmt.Println("request_token:         ", vm.request_token)
	fmt.Println("prefix:                ", vm.prefix)
	fmt.Println("origin_AS:             ", vm.origin_AS)
	fmt.Println("length_path_val_data:  ", vm.length_path_val_data)
	fmt.Println("num_of_hops:           ", vm.num_of_hops)
	fmt.Println("bgpsec_length:         ", vm.bgpsec_length)
	fmt.Println("afi:                   ", vm.afi)
	fmt.Println("safi:                  ", vm.safi)
	fmt.Println("prefix_len_bgpsec:     ", vm.prefix_len_bgpsec)
	fmt.Println("ip_pre_add_byte_a:     ", vm.ip_pre_add_byte_a)
	fmt.Println("ip_pre_add_byte_b:     ", vm.ip_pre_add_byte_b)
	fmt.Println("ip_pre_add_byte_c:     ", vm.ip_pre_add_byte_c)
	fmt.Println("ip_pre_add_byte_d:     ", vm.ip_pre_add_byte_d)
	fmt.Println("local_as:              ", vm.local_as)
	fmt.Println("as_path_list:          ", vm.as_path_list)
	fmt.Println("path_attribute:        ", vm.path_attribute)
	fmt.Println("+----------------------------------+")
}
