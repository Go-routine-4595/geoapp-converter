package model

import "time"

type Item struct {
	Rcv   time.Time
	Topic string
	Data  []byte
}
