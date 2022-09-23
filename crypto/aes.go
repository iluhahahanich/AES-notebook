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
	ivTemp := make([]byte, len(iv))
	copy(ivTemp, iv)
	inTemp := make([]byte, len(in))
	copy(inTemp, in)

	i := 0
	for ; i < len(inTemp)-a.len; i += a.len {
		a.encryptBlock(ivTemp)
		xor(inTemp[i:i+a.len], ivTemp)
	}
	a.encryptBlock(ivTemp)
	xor(inTemp[i:], ivTemp)

	return inTemp
}

// DecryptOFB returns the plaintext of OFB-mode decryption.
// The iv must be 128bit.
func (a *AES) DecryptOFB(in []byte, iv []byte) []byte {
	return a.EncryptOFB(in, iv)
}

func (a *AES) keyExpansion() []uint32 {
	w := make([]uint32, a.nb*(a.nr+1))
	for i := 0; i < a.nk; i++ {
		w[i] = binary.BigEndian.Uint32(a.key[4*i : 4*i+4])
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
		w[i] = w[i-a.nk] ^ binary.BigEndian.Uint32(temp)
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

func (a *AES) shiftRow(in []byte, i int, n int) {
	in[i], in[i+4*1], in[i+4*2], in[i+4*3] = in[i+4*(n%4)], in[i+4*((n+1)%4)], in[i+4*((n+2)%4)], in[i+4*((n+3)%4)]
}

func (a *AES) mixColumns(state []byte) {
	s := []byte{0x02, 0x01, 0x01, 0x03}
	for i := 0; i < len(state); i += 4 {
		mulColumn(state[i:i+4], s)
	}
}

func (a *AES) invMixColumns(state []byte) {
	s := []byte{0x0e, 0x09, 0x0d, 0x0b}
	for i := 0; i < len(state); i += 4 {
		mulColumn(state[i:i+4], s)
	}
}

func mulColumn(x []byte, y []byte) {
	x[0], x[1], x[2], x[3] =
		mulByte(x[0], y[0])^mulByte(x[1], y[3])^mulByte(x[2], y[2])^mulByte(x[3], y[1]),
		mulByte(x[0], y[1])^mulByte(x[1], y[0])^mulByte(x[2], y[3])^mulByte(x[3], y[1]),
		mulByte(x[0], y[2])^mulByte(x[1], y[1])^mulByte(x[2], y[3])^mulByte(x[3], y[3]),
		mulByte(x[0], y[0])^mulByte(x[1], y[1])^mulByte(x[2], y[2])^mulByte(x[3], y[3])
}

func mulByte(x byte, y byte) byte {
	res := byte(0)
	for counter := 0; counter < 8; counter++ {
		res ^= x * (y & 1)
		x = (x << 1) ^ ((x>>7)&1)*0x1b
		y >>= 1
	}
	return res
}

func (a *AES) addRoundKey(state []byte, w []uint32) {
	tmp := make([]byte, a.len)
	for i := 0; i < len(w); i += 1 {
		binary.BigEndian.PutUint32(tmp[4*i:4*i+4], w[i])
	}
	xor(state, tmp)
}
