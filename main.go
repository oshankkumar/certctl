package main

import (
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := NewCertCtl().Execute(); err != nil {
		log.Fatal(err)
	}
}
