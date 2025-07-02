package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"os"

	rtc "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_rtc"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func key(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	priv, _ := ec.PrivateKeyFromBytes(buf)
	return priv
}

func main() {
	outfile := "frames_go.json"
	if len(os.Args) > 1 {
		outfile = os.Args[1]
	}

	// deterministic keys + salts
	self := key(1)
	peer := key(2)
	saltA := []byte{1, 2, 3, 4}
	saltB := []byte{5, 6, 7, 8}

	sess, err := rtc.NewSession(self, peer.PubKey(), saltA, saltB)
	if err != nil {
		panic(err)
	}
	frag := rtc.NewFragmenter(sess)

	// 1 MiB random payload
	msg := make([]byte, 1<<20)
	_, _ = crand.Read(msg)
	digest := sha256.Sum256(msg)

	frames, err := frag.Encode(msg)
	if err != nil {
		panic(err)
	}
	mrand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })

	hexFrames := make([]string, len(frames))
	for i, f := range frames {
		hexFrames[i] = hex.EncodeToString(f)
	}

	out := map[string]interface{}{
		"digest": hex.EncodeToString(digest[:]),
		"frames": hexFrames,
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	if err := ioutil.WriteFile(outfile, data, 0644); err != nil {
		panic(err)
	}
	fmt.Println("[Go] frames written to", outfile)
}
