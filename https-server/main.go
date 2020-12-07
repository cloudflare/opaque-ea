package main

import (
	"log"

	"github.com/cloudflare/opaque-ea/src/ohttp"
)

func main() {
	err := ohttp.RunOpaqueServer()
	if err != nil {
		log.Println("Fatal error occurred while running OPAQUE server.")
	}
}
