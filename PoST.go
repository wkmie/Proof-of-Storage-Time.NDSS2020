package main

import (
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"math/big"
	"time"
)

// sha3 computes the SHA3-256 hash of data
func sha3Hash(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

// hmacSHA3 performs HMAC using SHA3-256 without the nested construction
func hmacSHA3(key, data []byte) []byte {
	h := sha3.New256()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}

// setup generates two large prime numbers (p, q)
func setup(nBits int) (*big.Int, *big.Int) {
	p, _ := rand.Prime(rand.Reader, nBits/2)
	q, _ := rand.Prime(rand.Reader, nBits/2)
	return p, q
}

// evalTrap computes modular exponentiation: r = x^e mod n
func evalTrap(x []byte, n, e *big.Int) []byte {
	bigX := new(big.Int).SetBytes(x)
	r := new(big.Int).Exp(bigX, e, n)
	return r.Bytes()
}

// eval performs repeated squaring: g = x^(2^t) mod n
func eval(x []byte, n *big.Int, t int) []byte {
	g := new(big.Int).SetBytes(x)
	for i := 0; i < (1 << t); i++ {
		g.Mul(g, g).Mod(g, n)
	}
	return g.Bytes()
}

// store function simulates storing the proof
func store(c, d []byte, p, q *big.Int, t, k int) ([]byte, []byte) {
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	e := new(big.Int).SetBit(big.NewInt(0), 1<<t, 1)
	e.Mod(e, phi)

	cs := []byte{}
	vs := []byte{}

	for i := 0; i <= k; i++ {
		v := hmacSHA3(c, d)
		cs = append(cs, c...)
		vs = append(vs, v...)
		c = sha3Hash(evalTrap(sha3Hash(v), n, e))
	}
	return sha3Hash(cs), sha3Hash(vs)
}

// prove function simulates verifying the proof
func prove(c, d []byte, n *big.Int, t, k int) ([]byte, []byte) {
	cs := []byte{}
	vs := []byte{}

	for i := 0; i <= k; i++ {
		v := hmacSHA3(c, d)
		cs = append(cs, c...)
		vs = append(vs, v...)
		c = sha3Hash(eval(sha3Hash(v), n, t))
	}
	return sha3Hash(cs), sha3Hash(vs)
}

func main() {
	const T = 27
	const NBits = 2048

	for k := 1; k < 5; k++ {
		for _, size := range []int{64, 128, 192, 256} {
			fmt.Printf("%d month(s), %d MB\n", k, size)

			c := make([]byte, 32)
			rand.Read(c)
			file := make([]byte, size*1024*1024)

			p, q := setup(NBits)

			now := time.Now()
			a1, a2 := store(c, file, p, q, T, k*720)
			fmt.Printf("store: %v\n", time.Since(now))

			now = time.Now()
			b1, b2 := prove(c, file, new(big.Int).Mul(p, q), T, k*720)
			fmt.Printf("prove: %v\n", time.Since(now))

			if !equal(a1, b1) || !equal(a2, b2) {
				panic("Proof verification failed!")
			}
		}
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
