/*
 * *******************************************************************
 * @项目名称: sssa-golang
 * @文件名称: sssa.go
 * @Date: 2019/03/06
 * @Author: yuqi.lin
 * @Copyright（C）: 2019 BlueHelix Inc.   All rights reserved.
 * 注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的.
 * *******************************************************************
 */
package sssa

import (
	"errors"
	"math/big"
)

var k = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

var (
	ErrCannotRequireMoreShares = errors.New("cannot require more shares then existing")
	ErrOneOfTheSharesIsInvalid = errors.New("one of the shares is invalid")
)

const (
	DefaultPrimeStr = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
)

type ShareXY struct {
	X, Y *big.Int
}

func init() {
	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)
}

/**
 * Returns a new arary of secret shares (encoding x,y pairs as base64 strings)
 * created by Shamir's Secret Sharing Algorithm requring a minimum number of
 * share to recreate, of length shares, from the input secret raw as a string
**/
func Create(minimum int, shares int, priKey *big.Int, coeff []*big.Int) (map[string]ShareXY, []*big.Int, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.

	// Convert the secret to its respective 256-bit big.Int representation
	//var secret []*big.Int = splitByteToInt([]byte(raw))
	copy := big.NewInt(0).Set(priKey)
	if copy.Cmp(prime) >= 0 {
		return nil, nil, errors.New("prikey too large")
	}
	// copy = copy.Mod(copy, prime)
	secret := big.NewInt(0).Set(copy)

	// List of currently used numbers in the polynomial
	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))
	var coefficients []*big.Int = make([]*big.Int, 0)

	// Create the polynomial of degree (minimum - 1); that is, the highest
	// order term is (minimum-1), though as there is a constant term with
	// order 0, there are (minimum) number of coefficients.
	//
	// However, the polynomial object is a 2d array, because we are constructing
	// a different polynomial for each part of the secret
	// polynomial[parts][minimum]
	polynomial := make([]*big.Int, minimum)
	polynomial[0] = secret

	for j := range polynomial[1:] {
		// Each coefficient should be unique
		number := random()
		for inNumbers(numbers, number) {
			number = random()
		}
		numbers = append(numbers, number)

		polynomial[j+1] = number
	}
	coefficients = polynomial

	// Create the secrets object; this holds the (x, y) points of each share.
	// Again, because secret is an array, each share could have multiple parts
	// over which we are computing Shamir's Algorithm. The last dimension is
	// always two, as it is storing an x, y pair of points.
	//
	// Note: this array is technically unnecessary due to creating result
	// in the inner loop. Can disappear later if desired. [TODO]
	//
	// secrets[shares][parts][2]
	var secrets [][]*big.Int = make([][]*big.Int, shares)
	var result map[string]ShareXY = make(map[string]ShareXY, shares)

	// For every share...
	for i := range secrets {
		secrets[i] = make([]*big.Int, 2)

		// ...generate a new x-coordinate...
		// number := random()
		// for inNumbers(numbers, number) {
		// 	number = random()
		// }
		//number := big.NewInt(int64(i + 1))
		number := big.NewInt(0).Set(coeff[i])
		numbers = append(numbers, number)

		// ...and evaluate the polynomial at that point...
		secrets[i][0] = number
		secrets[i][1] = evaluatePolynomial(polynomial, number)
		temp := ShareXY{
			X: secrets[i][0],
			Y: secrets[i][1],
		}
		result[coeff[i].String()] = temp
	}

	// ...and return!
	return result, coefficients, nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
**/
func Combine(shares map[string]ShareXY) (*big.Int, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets map[string][][]*big.Int = make(map[string][][]*big.Int)
	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// For each share...
	var coeffs []string
	for i, _ := range shares {
		coeffs = append(coeffs, i)

		// ...find the number of parts it represents...
		share := shares[i]

		secrets[i] = make([][]*big.Int, 1)

		// ...and for each part, find the x,y pair...
		for j := range secrets[i] {
			secrets[i][j] = make([]*big.Int, 2)
			// ...decoding from base 64.
			secrets[i][j][0] = share.X
			secrets[i][j][1] = share.Y
		}
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret []*big.Int = make([]*big.Int, len(secrets[coeffs[0]]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		// ...and every share...
		for i := range secrets { // LPI sum loop
			// ...remember the current x and y values...
			origin := secrets[i][j][0]
			originy := secrets[i][j][1]
			numerator := big.NewInt(1)   // LPI numerator
			denominator := big.NewInt(1) // LPI denominator
			// ...and for every other point...
			for k := range secrets { // LPI product loop
				if k != i {
					// ...combine them via half products...
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			// LPI product
			// ...multiply together the points (y)(numerator)(denominator)^-1...
			working := big.NewInt(0).Set(originy)
			working = working.Mul(working, numerator)
			working = working.Mul(working, modInverse(denominator))

			// LPI sum
			secret[j] = secret[j].Add(secret[j], working)
			secret[j] = secret[j].Mod(secret[j], prime)
		}
	}

	// ...and return the result!
	return secret[0], nil
}

//threshhold，计算下标为label的节点的bs值
func CalBs(participate []string, label string) (*big.Int, *big.Int) {
	// ...and every share...
	// ...and for every other point...
	origin, _ := big.NewInt(0).SetString(label, 10)
	numerator := big.NewInt(1)      // LPI numerator
	denominator := big.NewInt(1)    // LPI denominator
	for _, v := range participate { // LPI product loop
		if label != v {
			// ...combine them via half products...
			current, _ := big.NewInt(0).SetString(v, 10)
			negative := big.NewInt(0)
			negative = negative.Mul(current, big.NewInt(-1))
			added := big.NewInt(0)
			added = added.Sub(origin, current)

			numerator = numerator.Mul(numerator, negative)
			numerator = numerator.Mod(numerator, prime)

			denominator = denominator.Mul(denominator, added)
			denominator = denominator.Mod(denominator, prime)
		}
	}
	return numerator, denominator

	// LPI product
	// ...multiply together the points (y)(numerator)(denominator)^-1...

	// LPI su
}

func CalFinal(share, numer, denomi *big.Int) *big.Int {
	working := new(big.Int).Mul(share, numer)
	working = working.Mul(working, modInverse(denomi))
	working = working.Mod(working, prime)
	return working
}

func CalLi(number, denomi *big.Int) *big.Int {
	working := new(big.Int).Set(number)
	working = working.Mul(working, modInverse(denomi))
	working = working.Mod(working, prime)
	return working
}

/**
 * Takes in a given string to check if it is a valid secret
 *
 * Requirements:
 * 	Length multiple of 88
 *	Can decode each 44 character block as base64
 *
 * Returns only success/failure (bool)
**/
func IsValidShare(candidate string) bool {
	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	if len(candidate)%88 != 0 {
		return false
	}

	count := len(candidate) / 44
	for j := 0; j < count; j++ {
		part := candidate[j*44 : (j+1)*44]
		decode := fromBase64(part)
		if decode.Cmp(big.NewInt(0)) == -1 || decode.Cmp(prime) == 1 {
			return false
		}
	}

	return true
}
