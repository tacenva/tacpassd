package main

import (
	"log"

	"github.com/tacenva/tacpassd/internal/app"
)

func main() {
	if err := app.Run(true); err != nil {
		log.Fatal(err)
	}
}
