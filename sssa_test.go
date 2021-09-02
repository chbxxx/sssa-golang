package sssa

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyGen(t *testing.T) {
	T := 3
	N := 5
	var coeff []*big.Int = make([]*big.Int, N)
	coeff[0], _ = big.NewInt(0).SetString("12345", 10)
	coeff[1], _ = big.NewInt(0).SetString("23451", 10)
	coeff[2], _ = big.NewInt(0).SetString("34512", 10)
	coeff[3], _ = big.NewInt(0).SetString("45123", 10)
	coeff[4], _ = big.NewInt(0).SetString("51234", 10)

	prtKey, tempShareArray := keyGen(T, N, coeff)
	shareArray := make(map[string]ShareXY, 0)
	for i := 0; i < N; i++ {
		shareArray[coeff[i].String()] = tempShareArray[coeff[i].String()]
		combined, err := Combine(shareArray)
		if err != nil {
			t.Error("Fail to combine!")
		}
		if i < T-1 {
			assert.NotEqual(t, 0, combined.Cmp(prtKey), "The result is wrong!")
		} else {
			assert.Equal(t, 0, combined.Cmp(prtKey), "The result is wrong!")
		}

	}
}

func keyGen(t, n int, coeff []*big.Int) (*big.Int, map[string]ShareXY) {
	prime, _ := big.NewInt(0).SetString(DefaultPrimeStr, 10)
	newPriKey, _ := rand.Int(rand.Reader, prime)
	share, _ := Create(t, n, newPriKey, coeff)
	return newPriKey, share
}
