package main

import (
	"fmt"
	"log"
	"net"

	"github.com/davecgh/go-spew/spew"
	"github.com/titanous/weap/radius"
)

func main() {
	l, err := net.ListenPacket("udp4", "127.0.0.1:1812")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(radius.Serve(l, []byte("password"), radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		fmt.Println("writing response")
		spew.Dump(r, w.Write(&radius.Packet{Type: radius.TypeAccessAccept}))
	})))
}
