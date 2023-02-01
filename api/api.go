package api

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
)

const UnknownNamespace = ""

var UnknownIp = net.IP{0, 0, 0, 0}
var UnknownPort uint16 = 0

type Protocol struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Abbreviation    string   `json:"abbr"`
	LongName        string   `json:"longName"`
	Macro           string   `json:"macro"`
	BackgroundColor string   `json:"backgroundColor"`
	ForegroundColor string   `json:"foregroundColor"`
	FontSize        int8     `json:"fontSize"`
	ReferenceLink   string   `json:"referenceLink"`
	Ports           []string `json:"ports"`
	Layer4          string   `json:"layer4"`
	Priority        uint8    `json:"priority"`
}

type TCP struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
	Name string `json:"name"`
}

type Extension struct {
	Protocol  *Protocol
	Path      string
	Dissector Dissector
}

type ConnectionInfo struct {
	ClientIP   string
	ClientPort string
	ServerIP   string
	ServerPort string
	IsOutgoing bool
}

type TcpID struct {
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
	Ident   string
}

type CounterPair struct {
	Request  uint
	Response uint
	sync.Mutex
}

type GenericMessage struct {
	IsRequest   bool        `json:"isRequest"`
	CaptureTime time.Time   `json:"captureTime"`
	CaptureSize int         `json:"captureSize"`
	Payload     interface{} `json:"payload"`
}

type RequestResponsePair struct {
	Request  GenericMessage `json:"request"`
	Response GenericMessage `json:"response"`
}

// {Stream}-{Index} uniquely identifies an item
// `Protocol` is modified in later stages of data propagation. Therefore, it's not a pointer.
type OutputChannelItem struct {
	Index          int64
	Stream         string
	Protocol       Protocol
	Timestamp      int64
	ConnectionInfo *ConnectionInfo
	Pair           *RequestResponsePair
	Namespace      string
}

type ReadProgress struct {
	readBytes   int
	lastCurrent int
}

func (p *ReadProgress) Feed(n int) {
	p.readBytes += n
}

func (p *ReadProgress) Current() (n int) {
	p.lastCurrent = p.readBytes - p.lastCurrent
	return p.lastCurrent
}

func (p *ReadProgress) Reset() {
	p.readBytes = 0
	p.lastCurrent = 0
}

type Dissector interface {
	Register(*Extension)
	Dissect(b *bufio.Reader, reader TcpReader) error
	Analyze(item *OutputChannelItem, resolvedSource string, resolvedDestination string, namespace string) *Entry
	Summarize(entry *Entry) *BaseEntry
	Represent(request map[string]interface{}, response map[string]interface{}) (object []byte, err error)
	Macros() map[string]string
	NewResponseRequestMatcher() RequestResponseMatcher
}

type RequestResponseMatcher interface {
	GetMap() *sync.Map
	SetMaxTry(value int)
}

type Emitting struct {
	AppStats      *AppStats
	Stream        TcpStream
	OutputChannel chan *OutputChannelItem
}

type Emitter interface {
	Emit(item *OutputChannelItem)
}

func (e *Emitting) Emit(item *OutputChannelItem) {
	e.AppStats.IncMatchedPairs()
	e.Stream.SetAsEmittable()

	if !e.Stream.GetIsIdentifyMode() {
		item.Stream = e.Stream.GetPcapId()
		item.Index = e.Stream.GetIndex()
		e.Stream.IncrementItemCount()
		e.OutputChannel <- item
	}
}

type Node struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// {Worker}/{Stream}-{Index} uniquely identifies an item
type Entry struct {
	Id           string                 `json:"id"`
	Index        int64                  `json:"index"`
	Stream       string                 `json:"stream"`
	Worker       string                 `json:"worker"`
	Node         *Node                  `json:"node"`
	Protocol     Protocol               `json:"protocol"`
	Tls          bool                   `json:"tls"`
	Source       *TCP                   `json:"src"`
	Destination  *TCP                   `json:"dst"`
	Namespace    string                 `json:"namespace"`
	Outgoing     bool                   `json:"outgoing"`
	Timestamp    int64                  `json:"timestamp"`
	StartTime    time.Time              `json:"startTime"`
	Request      map[string]interface{} `json:"request"`
	Response     map[string]interface{} `json:"response"`
	RequestSize  int                    `json:"requestSize"`
	ResponseSize int                    `json:"responseSize"`
	ElapsedTime  int64                  `json:"elapsedTime"`
}

func (e *Entry) BuildId() {
	e.Id = fmt.Sprintf("%s/%s-%d", e.Worker, e.Stream, e.Index)
}

type EntryWrapper struct {
	Protocol       Protocol   `json:"protocol"`
	Representation string     `json:"representation"`
	Data           *Entry     `json:"data"`
	Base           *BaseEntry `json:"base"`
}

// {Worker}/{Id} uniquely identifies an item
type BaseEntry struct {
	Id           string   `json:"id"`
	Stream       string   `json:"stream"`
	Worker       string   `json:"worker"`
	Protocol     Protocol `json:"proto,omitempty"`
	Tls          bool     `json:"tls"`
	Summary      string   `json:"summary,omitempty"`
	SummaryQuery string   `json:"summaryQuery,omitempty"`
	Status       int      `json:"status"`
	StatusQuery  string   `json:"statusQuery"`
	Method       string   `json:"method,omitempty"`
	MethodQuery  string   `json:"methodQuery,omitempty"`
	Timestamp    int64    `json:"timestamp,omitempty"`
	Source       *TCP     `json:"src"`
	Destination  *TCP     `json:"dst"`
	Outgoing     bool     `json:"outgoing"`
	Latency      int64    `json:"latency"`
}

const (
	TABLE string = "table"
	BODY  string = "body"
)

type SectionData struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Data     string `json:"data"`
	Encoding string `json:"encoding,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Selector string `json:"selector,omitempty"`
}

type TableData struct {
	Name     string      `json:"name"`
	Value    interface{} `json:"value"`
	Selector string      `json:"selector"`
}

type TcpReaderDataMsg interface {
	GetBytes() []byte
	GetTimestamp() time.Time
	GetCaptureInfo() gopacket.CaptureInfo
}

type TcpReader interface {
	Read(p []byte) (int, error)
	GetReqResMatcher() RequestResponseMatcher
	GetIsClient() bool
	GetReadProgress() *ReadProgress
	GetParent() TcpStream
	GetTcpID() *TcpID
	GetCounterPair() *CounterPair
	GetCaptureTime() time.Time
	GetEmitter() Emitter
	GetIsClosed() bool
}

type TcpStream interface {
	SetProtocol(protocol *Protocol)
	SetAsEmittable()
	GetPcapId() string
	GetIndex() int64
	GetIsIdentifyMode() bool
	GetReqResMatchers() []RequestResponseMatcher
	GetIsTargeted() bool
	GetIsClosed() bool
	IncrementItemCount()
}

type TcpStreamMap interface {
	Range(f func(key, value interface{}) bool)
	Store(key, value interface{})
	Delete(key interface{})
	NextId() int64
	CloseTimedoutTcpStreamChannels()
}
