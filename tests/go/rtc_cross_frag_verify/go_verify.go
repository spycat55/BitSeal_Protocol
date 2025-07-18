package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	mrand "math/rand"
	"strings"

	rtc "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_rtc"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type Input struct {
	Digest string   `json:"digest"`
	Frames []string `json:"frames"`
}

func key2(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}

func main() {
	infile := "frames_ts.json"
	if len(os.Args) > 1 {
		infile = os.Args[1]
	}
	data, err := ioutil.ReadFile(infile)
	if err != nil {
		panic(err)
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		panic(err)
	}

	self := key2(1)
	peer := key2(2)
	saltA := []byte{1, 2, 3, 4}
	saltB := []byte{5, 6, 7, 8}

	// Note: we are decoding frames generated by TS using saltA as sender salt,
	// so our session must use saltA as recv salt (peerSalt).
	sess, _ := rtc.NewSession(self, peer.PubKey(), saltA, saltB)
	recv := rtc.NewReassembler(sess)

	// introduce shuffle and duplicates
	frames := append([]string(nil), in.Frames...)
	// Fisher-Yates shuffle
	for i := len(frames) - 1; i > 0; i-- {
		j := mrand.Intn(i + 1)
		frames[i], frames[j] = frames[j], frames[i]
	}
	// duplicate first up to 3 frames at random positions
	for k := 0; k < 3 && k < len(in.Frames); k++ {
		idx := mrand.Intn(len(frames))
		frames = append(frames[:idx], append([]string{in.Frames[k]}, frames[idx:]...)...)
	}

	var msg []byte
	for _, hexFrame := range frames {
		f, _ := hex.DecodeString(hexFrame)
		if plain, ok, err := recv.Push(f); err != nil {
			if strings.Contains(err.Error(), "replay") || strings.Contains(err.Error(), "old packet") {
				continue
			}
			panic(err)
		} else if ok {
			msg = plain
		}
	}
	if msg == nil {
		fmt.Println("[Go] failed to reassemble message")
		os.Exit(1)
	}
	digest := sha256.Sum256(msg)
	if hex.EncodeToString(digest[:]) != in.Digest {
		fmt.Println("[Go] digest mismatch")
		os.Exit(1)
	}
	fmt.Println("[Go] cross verification OK ")
}
