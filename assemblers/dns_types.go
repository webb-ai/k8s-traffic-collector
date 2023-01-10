package assemblers

import (
	"encoding/base64"
	"fmt"

	"github.com/kubeshark/gopacket/layers"
)

type dnsQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type dnsRequest struct {
	OpCode    string        `json:"opCode"`
	Questions []dnsQuestion `json:"questions"`
}

type dnsAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	IP    string `json:"ip"`
	NS    string `json:"ns"`
	CNAME string `json:"cname"`
	PTR   string `json:"ptr"`
	TXTs  string `json:"txts"`
	SOA   string `json:"soa"`
	SRV   string `json:"srv"`
	MX    string `json:"mx"`
	OPT   string `json:"opt"`
	URI   string `json:"uri"`
}

type dnsResponse struct {
	Code        string      `json:"code"`
	Answers     []dnsAnswer `json:"answers"`
	Authorities []dnsAnswer `json:"authorities"`
	Additionals []dnsAnswer `json:"additionals"`
}

func mapResourceRecordToAnswer(r layers.DNSResourceRecord) dnsAnswer {
	var txts string
	for _, txt := range r.TXTs {
		txts = fmt.Sprintf("%s, %s", txts, string(txt))
	}

	var opts string
	for _, opt := range r.OPT {
		opts = fmt.Sprintf("%s, %s", opts, opt.Code.String())
	}

	name := string(r.Name)
	b64, err := base64.StdEncoding.DecodeString(string(r.Name))
	if err == nil {
		name = string(b64)
	}

	return dnsAnswer{
		Name:  name,
		Type:  r.Type.String(),
		Class: r.Class.String(),
		TTL:   r.TTL,
		IP:    r.IP.String(),
		NS:    string(r.NS),
		CNAME: string(r.CNAME),
		PTR:   string(r.PTR),
		TXTs:  txts,
		SOA:   string(r.SOA.RName),
		SRV:   string(r.SRV.Name),
		MX:    string(r.MX.Name),
		OPT:   opts,
		URI:   string(r.URI.Target),
	}
}

func mapDNSLayerToRequest(dns *layers.DNS) dnsRequest {
	var questions []dnsQuestion
	for _, q := range dns.Questions {
		name := string(q.Name)
		b64, err := base64.StdEncoding.DecodeString(string(q.Name))
		if err == nil {
			name = string(b64)
		}

		questions = append(questions, dnsQuestion{
			Name:  name,
			Type:  q.Type.String(),
			Class: q.Class.String(),
		})
	}

	return dnsRequest{
		OpCode:    dns.OpCode.String(),
		Questions: questions,
	}
}

func mapDNSLayerToResponse(dns *layers.DNS) dnsResponse {
	var answers []dnsAnswer
	for _, r := range dns.Answers {
		answers = append(answers, mapResourceRecordToAnswer(r))
	}

	var authorities []dnsAnswer
	for _, r := range dns.Authorities {
		authorities = append(authorities, mapResourceRecordToAnswer(r))
	}

	var additionals []dnsAnswer
	for _, r := range dns.Additionals {
		additionals = append(additionals, mapResourceRecordToAnswer(r))
	}

	return dnsResponse{
		Code:        dns.ResponseCode.String(),
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}
}
