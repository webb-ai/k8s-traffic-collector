package dns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kubeshark/worker/pkg/api"
)

var dnsProtocol = api.Protocol{
	Name:            "dns",
	Version:         "0",
	Abbreviation:    "DNS",
	LongName:        "Domain Name System",
	Macro:           "dns",
	BackgroundColor: "#606060",
	ForegroundColor: "#ffffff",
	FontSize:        12,
	ReferenceLink:   "https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml",
	Ports:           []string{},
	Layer4:          "udp",
	Priority:        4,
}

type dissecting string

func (d dissecting) Register(extension *api.Extension) {
	extension.Protocol = &dnsProtocol
}

func (d dissecting) Dissect(b *bufio.Reader, reader api.TcpReader) error {
	return fmt.Errorf("N/A")
}

func (d dissecting) Analyze(item *api.OutputChannelItem, resolvedSource *api.Resolution, resolvedDestination *api.Resolution) *api.Entry {
	elapsedTime := item.Pair.Response.CaptureTime.Sub(item.Pair.Request.CaptureTime).Round(time.Millisecond).Milliseconds()
	if elapsedTime < 0 {
		elapsedTime = 0
	}

	return &api.Entry{
		Index:        item.Index,
		Stream:       item.Stream,
		Node:         &api.Node{},
		Protocol:     item.Protocol,
		Source:       resolvedSource,
		Destination:  resolvedDestination,
		Outgoing:     item.ConnectionInfo.IsOutgoing,
		Request:      item.Pair.Request.Payload.(map[string]interface{}),
		Response:     item.Pair.Response.Payload.(map[string]interface{}),
		RequestSize:  item.Pair.Request.CaptureSize,
		ResponseSize: item.Pair.Response.CaptureSize,
		Timestamp:    item.Timestamp,
		StartTime:    item.Pair.Request.CaptureTime,
		ElapsedTime:  elapsedTime,
	}
}

func (d dissecting) Summarize(entry *api.Entry) *api.BaseEntry {
	summary := string(entry.Request["questions"].([]interface{})[0].(map[string]interface{})["name"].(string))
	summaryQuery := fmt.Sprintf(`request.questions[0].name == "%s"`, summary)
	method := entry.Request["opCode"].(string)
	methodQuery := fmt.Sprintf(`request.opCode == %s`, method)
	status := 0
	statusQuery := ""

	return &api.BaseEntry{
		Id:           fmt.Sprintf("%s/%s-%d", entry.Worker, entry.Stream, entry.Index),
		Stream:       entry.Stream,
		Worker:       entry.Worker,
		Protocol:     entry.Protocol,
		Tls:          entry.Tls,
		Summary:      summary,
		SummaryQuery: summaryQuery,
		Status:       status,
		StatusQuery:  statusQuery,
		Method:       method,
		MethodQuery:  methodQuery,
		Timestamp:    entry.Timestamp,
		Source:       entry.Source,
		Destination:  entry.Destination,
		Outgoing:     entry.Outgoing,
		RequestSize:  entry.RequestSize,
		ResponseSize: entry.ResponseSize,
		ElapsedTime:  entry.ElapsedTime,
		Passed:       entry.Passed,
		Failed:       entry.Failed,
	}
}

func (d dissecting) Macros() map[string]string {
	return map[string]string{
		`dns`: fmt.Sprintf(`protocol.abbr == "%s"`, dnsProtocol.Abbreviation),
	}
}

func representRequest(request map[string]interface{}) (repRequest []interface{}) {
	details, _ := json.Marshal([]api.TableData{
		{
			Name:     "OpCode",
			Value:    request["opCode"].(string),
			Selector: `request.opCode`,
		},
	})
	repRequest = append(repRequest, api.SectionData{
		Type:  api.TABLE,
		Title: "Details",
		Data:  string(details),
	})

	for i, _question := range request["questions"].([]interface{}) {
		question, _ := json.Marshal([]api.TableData{
			{
				Name:     "Name",
				Value:    _question.(map[string]interface{})["name"].(string),
				Selector: fmt.Sprintf("request.questions[%d].name", i),
			},
			{
				Name:     "Type",
				Value:    _question.(map[string]interface{})["type"].(string),
				Selector: fmt.Sprintf("request.questions[%d].type", i),
			},
			{
				Name:     "Class",
				Value:    _question.(map[string]interface{})["class"].(string),
				Selector: fmt.Sprintf("request.questions[%d].class", i),
			},
		})
		repRequest = append(repRequest, api.SectionData{
			Type:  api.TABLE,
			Title: fmt.Sprintf("Question [%d]", i),
			Data:  string(question),
		})
	}

	return
}

func representAnswers(answers []interface{}, field string, title string, repResponse []interface{}) []interface{} {
	for i, _answer := range answers {
		answer, _ := json.Marshal([]api.TableData{
			{
				Name:     "Name",
				Value:    _answer.(map[string]interface{})["name"].(string),
				Selector: fmt.Sprintf("response.%s[%d].name", field, i),
			},
			{
				Name:     "Type",
				Value:    _answer.(map[string]interface{})["type"].(string),
				Selector: fmt.Sprintf("response.%s[%d].type", field, i),
			},
			{
				Name:     "Class",
				Value:    _answer.(map[string]interface{})["class"].(string),
				Selector: fmt.Sprintf("response.%s[%d].class", field, i),
			},
			{
				Name:     "TTL",
				Value:    _answer.(map[string]interface{})["ttl"].(float64),
				Selector: fmt.Sprintf("response.%s[%d].ttl", field, i),
			},
			{
				Name:     "IP",
				Value:    _answer.(map[string]interface{})["ip"].(string),
				Selector: fmt.Sprintf("response.%s[%d].ip", field, i),
			},
			{
				Name:     "NS",
				Value:    _answer.(map[string]interface{})["ns"].(string),
				Selector: fmt.Sprintf("response.%s[%d].ns", field, i),
			},
			{
				Name:     "CNAME",
				Value:    _answer.(map[string]interface{})["cname"].(string),
				Selector: fmt.Sprintf("response.%s[%d].cname", field, i),
			},
			{
				Name:     "PTR",
				Value:    _answer.(map[string]interface{})["ptr"].(string),
				Selector: fmt.Sprintf("response.%s[%d].ptr", field, i),
			},
			{
				Name:     "TXTs",
				Value:    _answer.(map[string]interface{})["txts"].(string),
				Selector: fmt.Sprintf("response.%s[%d].txts", field, i),
			},

			{
				Name:     "SOA",
				Value:    _answer.(map[string]interface{})["soa"].(string),
				Selector: fmt.Sprintf("response.%s[%d].soa", field, i),
			},
			{
				Name:     "SRV",
				Value:    _answer.(map[string]interface{})["srv"].(string),
				Selector: fmt.Sprintf("response.%s[%d].srv", field, i),
			},
			{
				Name:     "MX",
				Value:    _answer.(map[string]interface{})["mx"].(string),
				Selector: fmt.Sprintf("response.%s[%d].mx", field, i),
			},
			{
				Name:     "OPT",
				Value:    _answer.(map[string]interface{})["opt"].(string),
				Selector: fmt.Sprintf("response.%s[%d].opt", field, i),
			},
			{
				Name:     "URI",
				Value:    _answer.(map[string]interface{})["uri"].(string),
				Selector: fmt.Sprintf("response.%s[%d].uri", field, i),
			},
		})
		repResponse = append(repResponse, api.SectionData{
			Type:  api.TABLE,
			Title: fmt.Sprintf("%s [%d]", title, i),
			Data:  string(answer),
		})
	}

	return repResponse
}

func representResponse(response map[string]interface{}) (repResponse []interface{}) {
	details, _ := json.Marshal([]api.TableData{
		{
			Name:     "Code",
			Value:    response["code"].(string),
			Selector: `response.code`,
		},
	})
	repResponse = append(repResponse, api.SectionData{
		Type:  api.TABLE,
		Title: "Details",
		Data:  string(details),
	})

	if response["answers"] != nil {
		repResponse = representAnswers(response["answers"].([]interface{}), "answers", "Answer", repResponse)
	}

	if response["authorities"] != nil {
		repResponse = representAnswers(response["authorities"].([]interface{}), "authorities", "Authorities", repResponse)
	}

	if response["additionals"] != nil {
		repResponse = representAnswers(response["additionals"].([]interface{}), "additionals", "Additionals", repResponse)
	}

	return
}

func (d dissecting) Represent(request map[string]interface{}, response map[string]interface{}) (object []byte, err error) {
	representation := make(map[string]interface{})
	repRequest := representRequest(request)
	repResponse := representResponse(response)
	representation["request"] = repRequest
	representation["response"] = repResponse
	object, err = json.Marshal(representation)
	return
}

func (d dissecting) NewResponseRequestMatcher() api.RequestResponseMatcher {
	return nil
}

var Dissector dissecting

func NewDissector() api.Dissector {
	return Dissector
}
