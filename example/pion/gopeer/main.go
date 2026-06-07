// pion/webrtc DataChannel ping-pong demo with asio-ice.
// Usage: go run . [-server ws://localhost:8081/ws]
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	// "github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

func main() {
	addr := flag.String("server", "ws://localhost:8081/ws",
		"Signaling server URL")
	flag.Parse()

	u, err := url.Parse(*addr)
	if err != nil {
		log.Fatal("Invalid URL:", err)
	}

	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("WebSocket connect:", err)
	}
	defer ws.Close()
	log.Println("Connected to signaling server")

	settingEngine := webrtc.SettingEngine{}
	// settingEngine.SetICEMulticastDNSMode(
	// 	ice.MulticastDNSModeDisabled)

	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatal("NewPeerConnection:", err)
	}
	defer pc.Close()

	iceComplete := make(chan struct{})
	pongReceived := make(chan struct{})
	done := make(chan struct{})

	pc.OnICEConnectionStateChange(
		func(state webrtc.ICEConnectionState) {
			log.Printf("ICE state: %s", state)
			switch state {
			case webrtc.ICEConnectionStateConnected,
				webrtc.ICEConnectionStateCompleted,
				webrtc.ICEConnectionStateFailed,
				webrtc.ICEConnectionStateDisconnected:
				close(iceComplete)
			}
		})

	dc, err := pc.CreateDataChannel("pingpong", nil)
	if err != nil {
		log.Fatal("CreateDataChannel:", err)
	}
	log.Printf("Created data channel: %s", dc.Label())

	dc.OnOpen(func() {
		log.Println("DataChannel OPEN!")
		dc.SendText("ping")
		log.Println("Sent: ping")
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		text := string(msg.Data)
		log.Printf("Received on '%s': %s", dc.Label(), text)
		if text == "pong" {
			log.Println("Ping-pong SUCCESS!")
			close(pongReceived)
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		log.Fatal("CreateOffer:", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		log.Fatal("SetLocalDescription:", err)
	}

	gatherComplete := make(chan struct{})
	pc.OnICEGatheringStateChange(
		func(state webrtc.ICEGatheringState) {
			log.Printf("ICE gather state: %s", state)
			if state == webrtc.ICEGatheringStateComplete {
				close(gatherComplete)
			}
		})
	<-gatherComplete

	log.Println("Sending SDP offer")
	offerJSON, _ := json.Marshal(map[string]string{
		"type": "offer",
		"sdp":  pc.LocalDescription().SDP,
	})
	if err := ws.WriteMessage(websocket.TextMessage, offerJSON); err != nil {
		log.Fatal("ws write offer:", err)
	}

	_, msg, err := ws.ReadMessage()
	if err != nil {
		log.Fatal("ws read answer:", err)
	}
	var resp map[string]string
	if err := json.Unmarshal(msg, &resp); err != nil {
		log.Fatal("json parse:", err)
	}
	log.Println("Got SDP answer")

	answer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  resp["sdp"],
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		log.Fatal("SetRemoteDescription:", err)
	}

	log.Println("Waiting for ICE connection...")
	select {
	case <-iceComplete:
	case <-time.After(30 * time.Second):
		log.Fatal("ICE connection timeout")
	}

	finalState := pc.ICEConnectionState()
	log.Printf("Final ICE state: %s", finalState)

	if finalState != webrtc.ICEConnectionStateConnected &&
		finalState != webrtc.ICEConnectionStateCompleted {
		log.Fatal("ICE did not connect successfully")
	}

	go func() {
		select {
		case <-pongReceived:
			log.Println("Done!")
		case <-time.After(30 * time.Second):
			log.Fatal("Pong timeout")
		}
		close(done)
	}()

	log.Println("Waiting for pong...")
	<-done
}
