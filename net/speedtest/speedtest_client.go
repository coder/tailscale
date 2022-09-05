// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package speedtest

import (
	"encoding/json"
	"errors"
	"net"
	"time"
)

// RunClient dials the given address and starts a speedtest.
// It returns any errors that come up in the tests.
// If there are no errors in the test, it returns a slice of results.
func RunClient(direction Direction, duration time.Duration, host string) ([]Result, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	return RunClientWithConn(direction, duration, conn)
}

func RunClientWithConn(direction Direction, duration time.Duration, conn net.Conn) ([]Result, error) {
	conf := config{TestDuration: duration, Version: version, Direction: direction}

	defer conn.Close()
	encoder := json.NewEncoder(conn)

	if err := encoder.Encode(conf); err != nil {
		return nil, err
	}

	var response configResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&response); err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return doTest(conn, conf)
}
