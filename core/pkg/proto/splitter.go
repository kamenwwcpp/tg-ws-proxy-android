package proto

import (
	"encoding/binary"
)

// MsgSplitter splits raw TCP stream data into individual MTProto packets
// so each can be forwarded as a distinct WebSocket binary frame.
type MsgSplitter struct {
	proto     uint32
	cipherBuf []byte
	plainBuf  []byte
	disabled  bool
}

// NewMsgSplitter creates a new splitter for the given protocol tag.
func NewMsgSplitter(proto uint32) *MsgSplitter {
	return &MsgSplitter{
		proto:     proto,
		cipherBuf: make([]byte, 0, 4096),
		plainBuf:  make([]byte, 0, 4096),
	}
}

// Split processes incoming chunk (ciphertext) and plain (decrypted) data,
// returning full MTProto packet frames.
func (s *MsgSplitter) Split(chunk, plain []byte) [][]byte {
	if len(chunk) == 0 {
		return nil
	}
	if s.disabled {
		res := make([]byte, len(chunk))
		copy(res, chunk)
		return [][]byte{res}
	}

	s.cipherBuf = append(s.cipherBuf, chunk...)
	s.plainBuf = append(s.plainBuf, plain...)

	var parts [][]byte
	offset := 0
	bufLen := len(s.cipherBuf)

	for offset < bufLen {
		packetLen := s.nextPacketLen(offset, bufLen-offset)
		if packetLen < 0 {
			// Need more data
			break
		}
		if packetLen == 0 {
			// Malformed or disabled
			var tail []byte
			if offset == 0 {
				tail = make([]byte, len(s.cipherBuf))
				copy(tail, s.cipherBuf)
			} else {
				tail = make([]byte, len(s.cipherBuf)-offset)
				copy(tail, s.cipherBuf[offset:])
			}
			parts = append(parts, tail)
			offset = bufLen
			s.disabled = true
			break
		}

		packet := make([]byte, packetLen)
		copy(packet, s.cipherBuf[offset:offset+packetLen])
		parts = append(parts, packet)
		offset += packetLen
	}

	if offset > 0 {
		rem := len(s.cipherBuf) - offset
		copy(s.cipherBuf, s.cipherBuf[offset:])
		s.cipherBuf = s.cipherBuf[:rem]

		copy(s.plainBuf, s.plainBuf[offset:])
		s.plainBuf = s.plainBuf[:rem]
	}

	return parts
}

// Flush returns any remaining bytes in the buffer when the stream ends.
func (s *MsgSplitter) Flush() [][]byte {
	if len(s.cipherBuf) == 0 {
		return nil
	}
	tail := make([]byte, len(s.cipherBuf))
	copy(tail, s.cipherBuf)
	s.cipherBuf = s.cipherBuf[:0]
	s.plainBuf = s.plainBuf[:0]
	return [][]byte{tail}
}

// nextPacketLen determines the length of the next MTProto packet.
// Returns:
//   > 0: packet length in bytes
//   -1: need more data
//    0: invalid/disabled
func (s *MsgSplitter) nextPacketLen(offset, avail int) int {
	if avail <= 0 {
		return -1
	}

	switch s.proto {
	case ProtoAbridgedInt:
		return s.nextAbridgedLen(offset, avail)
	case ProtoIntermediateInt, ProtoPaddedIntermediateInt:
		return s.nextIntermediateLen(offset, avail)
	default:
		return 0
	}
}

func (s *MsgSplitter) nextAbridgedLen(offset, avail int) int {
	first := s.plainBuf[offset]
	var payloadLen int
	var headerLen int

	if first == 0x7F || first == 0xFF {
		if avail < 4 {
			return -1
		}
		lenBytes := s.plainBuf[offset+1 : offset+4]
		rawLen := int(lenBytes[0]) | (int(lenBytes[1]) << 8) | (int(lenBytes[2]) << 16)
		payloadLen = rawLen * 4
		headerLen = 4
	} else {
		payloadLen = int(first&0x7F) * 4
		headerLen = 1
	}

	if payloadLen <= 0 {
		return 0
	}

	packetLen := headerLen + payloadLen
	if avail < packetLen {
		return -1
	}
	return packetLen
}

func (s *MsgSplitter) nextIntermediateLen(offset, avail int) int {
	if avail < 4 {
		return -1
	}
	rawLen := binary.LittleEndian.Uint32(s.plainBuf[offset : offset+4])
	payloadLen := int(rawLen & 0x7FFFFFFF)
	if payloadLen <= 0 {
		return 0
	}
	packetLen := 4 + payloadLen
	if avail < packetLen {
		return -1
	}
	return packetLen
}
