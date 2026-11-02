package main

import (
	"flag"
	"fmt"
	"net"
	"time"
)

const (
	typeA   = 1
	classIN = 1

	rcodeNotImplemented = 4
)

func main() {
	resolver := flag.String("resolver", "", "upstream DNS resolver address (ip:port) to forward queries to")
	flag.Parse()

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	if *resolver != "" {
		fmt.Println("Forwarding queries to", *resolver)
	}

	buf := make([]byte, 512)
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		request := append([]byte(nil), buf[:size]...)
		go func() {
			response, err := handle(request, *resolver)
			if err != nil {
				fmt.Println("Failed to handle request:", err)
				return
			}
			if _, err := udpConn.WriteToUDP(response, source); err != nil {
				fmt.Println("Failed to send response:", err)
			}
		}()
	}
}

// handle builds the response for a single query. With no resolver configured
// every question is answered with a fixed A record; otherwise each question is
// forwarded upstream separately and the answers are merged.
func handle(request []byte, resolver string) ([]byte, error) {
	query, err := ParseMessage(request)
	if err != nil {
		return nil, err
	}

	response := Message{
		Header: Header{
			ID:     query.Header.ID,
			QR:     true,
			Opcode: query.Header.Opcode,
			RD:     query.Header.RD,
		},
		Questions: query.Questions,
	}
	if query.Header.Opcode != 0 {
		response.Header.RCode = rcodeNotImplemented
	}

	for _, q := range query.Questions {
		if resolver == "" {
			response.Answers = append(response.Answers, Record{
				Name:  q.Name,
				Type:  typeA,
				Class: classIN,
				TTL:   60,
				Data:  []byte{8, 8, 8, 8},
			})
			continue
		}

		answers, err := forward(resolver, query.Header, q)
		if err != nil {
			return nil, err
		}
		response.Answers = append(response.Answers, answers...)
	}

	return response.Encode(), nil
}

// forward sends a single-question query to the resolver and returns its answers.
func forward(resolver string, header Header, q Question) ([]Record, error) {
	conn, err := net.Dial("udp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	query := Message{Header: header, Questions: []Question{q}}
	if _, err := conn.Write(query.Encode()); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	reply, err := ParseMessage(buf[:n])
	if err != nil {
		return nil, err
	}
	return reply.Answers, nil
}
