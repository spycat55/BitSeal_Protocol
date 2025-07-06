package main

import (
    "fmt"

    // 直接引用 bitseal_rtc 包
    rtc "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_rtc"
)

func main() {
    fmt.Println("BitSeal-RTC constants:", rtc.FRAG_SIZE, rtc.MAX_FRAGS)
}