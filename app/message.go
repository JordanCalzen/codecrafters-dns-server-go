package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

const headerSize = 12

var errMalformed = errors.New("malformed DNS message")

// Header is the 12-byte DNS message header (RFC 1035 section 4.1.1).
type Header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question is an entry in the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Record is a resource record in the answer section.
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Message is a DNS message. Authority and additional sections are not needed
// by this server and are ignored when parsing.
type Message struct {
	Header    Header
	Questions []Question
	Answers   []Record
}

func (h Header) encode() []byte {
	buf := make([]byte, headerSize)
	binary.BigEndian.PutUint16(buf[0:], h.ID)

	var flags uint16
	if h.QR {
		flags |= 1 << 15
	}
	flags |= uint16(h.Opcode&0x0F) << 11
	if h.AA {
		flags |= 1 << 10
	}
	if h.TC {
		flags |= 1 << 9
	}
	if h.RD {
		flags |= 1 << 8
	}
	if h.RA {
		flags |= 1 << 7
	}
	flags |= uint16(h.Z&0x07) << 4
	flags |= uint16(h.RCode & 0x0F)
	binary.BigEndian.PutUint16(buf[2:], flags)

	binary.BigEndian.PutUint16(buf[4:], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:], h.ARCount)
	return buf
}

func parseHeader(buf []byte) (Header, error) {
	if len(buf) < headerSize {
		return Header{}, errMalformed
	}
	flags := binary.BigEndian.Uint16(buf[2:])
	return Header{
		ID:      binary.BigEndian.Uint16(buf[0:]),
		QR:      flags&(1<<15) != 0,
		Opcode:  uint8(flags>>11) & 0x0F,
		AA:      flags&(1<<10) != 0,
		TC:      flags&(1<<9) != 0,
		RD:      flags&(1<<8) != 0,
		RA:      flags&(1<<7) != 0,
		Z:       uint8(flags>>4) & 0x07,
		RCode:   uint8(flags) & 0x0F,
		QDCount: binary.BigEndian.Uint16(buf[4:]),
		ANCount: binary.BigEndian.Uint16(buf[6:]),
		NSCount: binary.BigEndian.Uint16(buf[8:]),
		ARCount: binary.BigEndian.Uint16(buf[10:]),
	}, nil
}

// encodeName writes a domain name as a sequence of length-prefixed labels
// terminated by a zero byte. Names are always written uncompressed.
func encodeName(name string) []byte {
	var buf []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

// parseName reads a possibly compressed domain name starting at offset and
// returns the name and the offset just past it in the original stream.
func parseName(buf []byte, offset int) (string, int, error) {
	var labels []string
	next := -1 // where parsing resumes after the first pointer jump
	for jumps := 0; ; {
		if offset >= len(buf) {
			return "", 0, errMalformed
		}
		length := int(buf[offset])
		switch {
		case length == 0:
			if next < 0 {
				next = offset + 1
			}
			return strings.Join(labels, "."), next, nil
		case length&0xC0 == 0xC0:
			if offset+1 >= len(buf) {
				return "", 0, errMalformed
			}
			// Guard against pointer loops.
			if jumps++; jumps > len(buf) {
				return "", 0, errMalformed
			}
			if next < 0 {
				next = offset + 2
			}
			offset = int(binary.BigEndian.Uint16(buf[offset:]) & 0x3FFF)
		default:
			offset++
			if offset+length > len(buf) {
				return "", 0, errMalformed
			}
			labels = append(labels, string(buf[offset:offset+length]))
			offset += length
		}
	}
}

func (q Question) encode() []byte {
	buf := encodeName(q.Name)
	buf = binary.BigEndian.AppendUint16(buf, q.Type)
	return binary.BigEndian.AppendUint16(buf, q.Class)
}

func (r Record) encode() []byte {
	buf := encodeName(r.Name)
	buf = binary.BigEndian.AppendUint16(buf, r.Type)
	buf = binary.BigEndian.AppendUint16(buf, r.Class)
	buf = binary.BigEndian.AppendUint32(buf, r.TTL)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Data)))
	return append(buf, r.Data...)
}

// Encode serializes the message, setting the section counts from the slices.
func (m Message) Encode() []byte {
	h := m.Header
	h.QDCount = uint16(len(m.Questions))
	h.ANCount = uint16(len(m.Answers))
	h.NSCount = 0
	h.ARCount = 0

	buf := h.encode()
	for _, q := range m.Questions {
		buf = append(buf, q.encode()...)
	}
	for _, r := range m.Answers {
		buf = append(buf, r.encode()...)
	}
	return buf
}

// ParseMessage decodes the header, question and answer sections.
func ParseMessage(buf []byte) (Message, error) {
	h, err := parseHeader(buf)
	if err != nil {
		return Message{}, err
	}
	m := Message{Header: h}
	offset := headerSize

	for i := 0; i < int(h.QDCount); i++ {
		name, next, err := parseName(buf, offset)
		if err != nil {
			return Message{}, err
		}
		if next+4 > len(buf) {
			return Message{}, errMalformed
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[next:]),
			Class: binary.BigEndian.Uint16(buf[next+2:]),
		})
		offset = next + 4
	}

	for i := 0; i < int(h.ANCount); i++ {
		name, next, err := parseName(buf, offset)
		if err != nil {
			return Message{}, err
		}
		if next+10 > len(buf) {
			return Message{}, errMalformed
		}
		dataLen := int(binary.BigEndian.Uint16(buf[next+8:]))
		dataStart := next + 10
		if dataStart+dataLen > len(buf) {
			return Message{}, errMalformed
		}
		m.Answers = append(m.Answers, Record{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[next:]),
			Class: binary.BigEndian.Uint16(buf[next+2:]),
			TTL:   binary.BigEndian.Uint32(buf[next+4:]),
			Data:  append([]byte(nil), buf[dataStart:dataStart+dataLen]...),
		})
		offset = dataStart + dataLen
	}

	return m, nil
}
