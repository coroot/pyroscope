package main

/*
static int cgo_add(int a, int b) { return a + b; }
*/
import "C"

import "fmt"

func main() {
	fmt.Println("hello, world", C.cgo_add(40, 2))
}
