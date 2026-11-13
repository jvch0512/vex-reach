package main

import (
	"fmt"

	"example.com/gzipx"
)

func main() {
	out := gzipx.Deflate([]byte("hello"))
	fmt.Println(len(out))
	// gzipx.Inflate is not used here
}
