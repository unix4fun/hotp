package hotp

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

const (
	rfc4226Secret = "12345678901234567890"
)

var (
	hmacRFCTestVector = map[int]string{
		0: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
		1: "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
		2: "0bacb7fa082fef30782211938bc1c5e70416ff44",
		3: "66c28227d03a2d5529262ff016a1e6ef76557ece",
		4: "a904c900a64b35909874b33e61c5938a8e15ed1c",
		5: "a37e783d7b7233c083d4f62926c7a25f238d0316",
		6: "bc9cd28561042c83f219324d3c607256c03272ae",
		7: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
		8: "1b3c89f65e6c9e883012052823443f048b4332db",
		9: "1637409809a679dc698207310c8c7fc07290d9e5",
	}

	hotpRfcTestVector = map[int]int{
		0: 755224,
		1: 287082,
		2: 359152,
		3: 969429,
		4: 338314,
		5: 254676,
		6: 287922,
		7: 162583,
		8: 399871,
		9: 520489,
	}
)

func TestVectorHmacCounter(t *testing.T) {

	for key, value := range hmacRFCTestVector {
		h := NewHotp(sha1.New, []byte(rfc4226Secret), 6)
		out, err := h.hmacCounter(uint64(key))
		if err != nil {
			t.Fatalf("[vector: %d] HMAC error: %v", key, err)
		}

		outString := hex.EncodeToString(out)
		if value != outString {
			t.Fatalf("[vector: %d] -> expected: %s vs %s", key, value, outString)
		}

		t.Logf("vector: %d out: %s expect: %s", key, outString, value)
	}

}

func TestVectorHotp(t *testing.T) {
	for key, value := range hotpRfcTestVector {
		h := NewHotp(sha1.New, []byte(rfc4226Secret), 6)

		out, err := h.Get(uint64(key))
		if err != nil {
			t.Fatalf("[vector: %d] HMAC error: %v", key, err)
		}
		t.Logf("vector: %d out: %d expect: %d", key, out, value)

		if uint32(value) != out {
			t.Fatalf("[vector: %d] -> expected: %d vs %d", key, value, out)
		}
	}
}
