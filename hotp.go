package hotp

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"hash"
	"math"
)

const (
	counterSize  = 8 // uint64
	DefaultDigit = 6 // the number of HOTP digit
)

var (
	ErrHMAC = errors.New("HMAC error")
)

type Hotp struct {
	secret []byte
	digit  uint32
	hm     hash.Hash
}

func NewHotp(f func() hash.Hash, s []byte, d int) *Hotp {
	digit := DefaultDigit

	// 6, 7 or 8 digits!!
	switch d {
	case 7, 8:
		digit = d
	}

	h := &Hotp{
		secret: s,                                             // the secret
		digit:  uint32(math.Pow(float64(10), float64(digit))), // the modulo
		hm:     hmac.New(f, s),                                // the hmac function setup
	}

	return h
}

// internal it returns the hash
func (h *Hotp) hmacCounter(c uint64) (out []byte, err error) {
	buf := make([]byte, counterSize)
	binary.BigEndian.PutUint64(buf, c)
	n, err := h.hm.Write(buf)
	if err != nil || n != counterSize {
		return
	}
	out = h.hm.Sum(nil)
	return
}

// XXX invalid if SHA256 or SHA512
func (h *Hotp) dt(hash []byte) uint32 {
	/* handle error
	if len(hash) < 20 {
	}
	*/
	offset := hash[19] & 0x0f
	dbc1 := hash[offset : offset+4]
	dbc1[0] = dbc1[0] & 0x7f
	dbc2 := binary.BigEndian.Uint32(dbc1)
	return uint32(dbc2 % h.digit)
}

func (h *Hotp) Get(c uint64) (uint32, error) {
	out, err := h.hmacCounter(c)
	if err != nil {
		return 0, ErrHMAC
	}
	return h.dt(out), nil
}
