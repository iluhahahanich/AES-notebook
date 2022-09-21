package crypto

import (
	"encoding/binary"
	"errors"
)

type AES struct {
	nr        int      // number of rounds
	nk        int      // number of words in the key
	nb        int      // number of words in a block
	len       int      // length(byte) of block
	key       []byte   // key
	roundKeys []uint32 // round keys generated from key.
}

func NewAES(key []byte) (*AES, error) {
	l := len(key)
	if l != 16 && l != 24 && l != 32 {
		return nil, errors.New("invalid key length")
	}
	aes := AES{
		nr:  l/4 + 6,
		nk:  l / 4,
		nb:  4,
		len: 16,
		key: key,
	}
	aes.roundKeys = aes.keyExpansion()
	return &aes, nil
}

// EncryptOFB returns the cipher of OFB-mode encryption.
// The iv must be 128bit.
func (a *AES) EncryptOFB(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	plainTmp := make([]byte, len(in))
	copy(plainTmp, in)

	i := 0
	for ; i < len(plainTmp)-a.len; i += a.len {
		a.encryptBlock(ivTmp)
		xor(plainTmp[i:i+a.len], ivTmp)
	}
	a.encryptBlock(ivTmp)
	xor(plainTmp[i:], ivTmp)

	return plainTmp
}

// DecryptOFB returns the plaintext of OFB-mode decryption.
// The iv must be 128bit.
func (a *AES) DecryptOFB(in []byte, iv []byte) []byte {
	return a.EncryptOFB(in, iv)
}

// keyExpansion returns an uint32 slice presenting round keys
// (4 uint32 for a key) in encryption. The number of round keys
// is determined by the type of encryption. For example, 11 round
// keys in AES-128.
func (a *AES) keyExpansion() []uint32 {
	var w []uint32
	for i := 0; i < a.nk; i++ {
		w = append(w, binary.BigEndian.Uint32(a.key[4*i:4*i+4]))
	}
	for i := a.nk; i < a.nb*(a.nr+1); i++ {
		temp := make([]byte, 4)
		binary.BigEndian.PutUint32(temp, w[i-1])
		if i%a.nk == 0 {
			rotWord(temp)
			a.subBytes(temp)
			xor(temp, rcon[i/a.nk-1])
		} else if a.nk > 6 && i%a.nk == 4 {
			a.subBytes(temp)
		}
		w = append(w, w[i-a.nk]^binary.BigEndian.Uint32(temp))
	}
	return w
}

func rotWord(in []byte) {
	in[0], in[1], in[2], in[3] = in[1], in[2], in[3], in[0]
}

func xor(x []byte, y []byte) {
	if len(x) <= len(y) {
		for i := 0; i < len(x); i++ {
			x[i] = x[i] ^ y[i]
		}
	}
}

func (a *AES) encryptBlock(state []byte) {
	a.addRoundKey(state, a.roundKeys[:4])
	for round := 1; round < a.nr; round++ {
		a.subBytes(state)
		a.shiftRows(state)
		a.mixColumns(state)
		a.addRoundKey(state, a.roundKeys[4*round:4*round+4])
	}
	a.subBytes(state)
	a.shiftRows(state)
	a.addRoundKey(state, a.roundKeys[a.nr*4:a.nr*4+4])
}

func (a *AES) decryptBlock(state []byte) {
	a.addRoundKey(state, a.roundKeys[a.nr*4:a.nr*4+4])
	for round := a.nr - 1; round > 0; round-- {
		a.invShiftRows(state)
		a.invSubBytes(state)
		a.addRoundKey(state, a.roundKeys[4*round:4*round+4])
		a.invMixColumns(state)
	}
	a.invShiftRows(state)
	a.invSubBytes(state)
	a.addRoundKey(state, a.roundKeys[:4])
}

func (a *AES) subBytes(state []byte) {
	for i, v := range state {
		state[i] = sbox[v]
	}
}

func (a *AES) invSubBytes(state []byte) {
	for i, v := range state {
		state[i] = invSbox[v]
	}
}

func (a *AES) shiftRow(in []byte, i int, n int) {
	in[i], in[i+4*1], in[i+4*2], in[i+4*3] = in[i+4*(n%4)], in[i+4*((n+1)%4)], in[i+4*((n+2)%4)], in[i+4*((n+3)%4)]
}

func (a *AES) shiftRows(state []byte) {
	a.shiftRow(state, 1, 1)
	a.shiftRow(state, 2, 2)
	a.shiftRow(state, 3, 3)
}

func (a *AES) invShiftRows(state []byte) {
	a.shiftRow(state, 1, 3)
	a.shiftRow(state, 2, 2)
	a.shiftRow(state, 3, 1)
}

// xtime returns the result of multiplication by x in GF(2^8).
func xtime(in byte) byte {
	return (in << 1) ^ (((in >> 7) & 1) * 0x1b)
}

// xtimes returns the result of multiplication by x^ts in GF(2^8).
func xtimes(in byte, ts int) byte {
	for ; ts > 0; ts-- {
		in = xtime(in)
	}
	return in
}

// mulByte returns byte x multiplied by byte y in GF(2^8).
func mulByte(x byte, y byte) byte {
	return (((y >> 0) & 0x01) * xtimes(x, 0)) ^
		(((y >> 1) & 0x01) * xtimes(x, 1)) ^
		(((y >> 2) & 0x01) * xtimes(x, 2)) ^
		(((y >> 3) & 0x01) * xtimes(x, 3)) ^
		(((y >> 4) & 0x01) * xtimes(x, 4)) ^
		(((y >> 5) & 0x01) * xtimes(x, 5)) ^
		(((y >> 6) & 0x01) * xtimes(x, 6)) ^
		(((y >> 7) & 0x01) * xtimes(x, 7))
}

// mulWord provides the one-column mix for the function
// mixColumns and invMixColumns. In fact, it's a matrix
// multiplication.
func mulWord(x []byte, y []byte) {
	tmp := make([]byte, 4)
	copy(tmp, x)

	x[0] = mulByte(tmp[0], y[3]) ^ mulByte(tmp[1], y[0]) ^ mulByte(tmp[2], y[1]) ^ mulByte(tmp[3], y[2])
	x[1] = mulByte(tmp[0], y[2]) ^ mulByte(tmp[1], y[3]) ^ mulByte(tmp[2], y[0]) ^ mulByte(tmp[3], y[1])
	x[2] = mulByte(tmp[0], y[1]) ^ mulByte(tmp[1], y[2]) ^ mulByte(tmp[2], y[3]) ^ mulByte(tmp[3], y[0])
	x[3] = mulByte(tmp[0], y[0]) ^ mulByte(tmp[1], y[1]) ^ mulByte(tmp[2], y[2]) ^ mulByte(tmp[3], y[3])
}

func (a *AES) mixColumns(state []byte) {
	s := []byte{0x03, 0x01, 0x01, 0x02}
	for i := 0; i < len(state); i += 4 {
		mulWord(state[i:i+4], s)
	}
}

func (a *AES) invMixColumns(state []byte) {
	s := []byte{0x0b, 0x0d, 0x09, 0x0e}
	for i := 0; i < len(state); i += 4 {
		mulWord(state[i:i+4], s)
	}
}

func (a *AES) addRoundKey(state []byte, w []uint32) {
	tmp := make([]byte, a.len)
	for i := 0; i < len(w); i += 1 {
		binary.BigEndian.PutUint32(tmp[4*i:4*i+4], w[i])
	}
	xor(state, tmp)
}
