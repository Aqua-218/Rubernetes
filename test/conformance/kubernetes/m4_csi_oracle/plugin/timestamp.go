package main

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func timestampOf(value time.Time) *timestamppb.Timestamp {
	return timestamppb.New(value)
}
