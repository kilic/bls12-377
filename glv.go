package bls12377

import (
	"math/big"
)

// Guide to Pairing Based Cryptography
// 6.3.2. Decompositions for the k = 12 BLS Family

// glvQ1 = x^2 * R / q
var glvQ1 = &Fr{0x7f72ed32af90182c, 0xb3f7aa969fd37160, 0x03, 0}
var glvQ1Big = bigFromHex("0x3b3f7aa969fd371607f72ed32af90182c")

// glvQ2 = R / q = 14
// var glvQ2 = &Fr{0x0e, 0, 0, 0}
var glvQ2 = &Fr{0x0d, 0, 0, 0}

var glvQ2Big = bigFromHex("0x0e")

// glvB1 = x^2 - 1 = 0x452217cc900000010a11800000000000
var glvB1 = &Fr{0x0a11800000000000, 0x452217cc90000001, 0, 0}
var glvB1Big = bigFromHex("0x452217cc900000010a11800000000000")

// glvB2 = x^2 = 0x452217cc900000010a11800000000001
var glvB2 = &Fr{0x0a11800000000001, 0x452217cc90000001, 0, 0}
var glvB2Big = bigFromHex("0x452217cc900000010a11800000000001")

// glvLambda = x^2 - 1
var glvLambda = &Fr{0x0a11800000000000, 0x452217cc90000001, 0, 0}
var glvLambdaBig = bigFromHex("0x452217cc900000010a11800000000000")

// r128 = 2**128 - 1
var r128 = &Fr{0xffffffffffffffff, 0xffffffffffffffff, 0, 0}

// glvPhi1 ^ 3 = 1
var glvPhi1 = &fe{0xdacd106da5847973, 0xd8fe2454bac2a79a, 0x1ada4fd6fd832edc, 0xfb9868449d150908, 0xd63eb8aeea32285e, 0x167d6a36f873fd0}

// glvPhi2 ^ 3 = 1
var glvPhi2 = &fe{0x2c766f925a7b8727, 0x03d7f6b0253d58b5, 0x838ec0deec122131, 0xbd5eb3e9f658bb10, 0x6942bd126ed3e52e, 0x01673786dd04ed6a}

var glvMulWindowG1 uint = 4
var glvMulWindowG2 uint = 4

type glvVector interface {
	wnaf(w uint) (nafNumber, nafNumber)
}

type glvVectorFr struct {
	k1   *Fr
	k2   *Fr
	neg1 bool
	neg2 bool
}

type glvVectorBig struct {
	k1 *big.Int
	k2 *big.Int
}

func (v *glvVectorFr) wnaf(w uint) (nafNumber, nafNumber) {
	naf1 := v.k1.toWNAF(w)
	naf2 := v.k2.toWNAF(w)
	if v.neg1 {
		naf1.neg()
	}
	if !v.neg2 {
		naf2.neg()
	}
	return naf1, naf2
}

func (v *glvVectorBig) wnaf(w uint) (nafNumber, nafNumber) {
	naf1, naf2 := bigToWNAF(v.k1, w), bigToWNAF(v.k2, w)
	zero := new(big.Int)
	if v.k1.Cmp(zero) < 0 {
		naf1.neg()
	}
	if v.k2.Cmp(zero) > 0 {
		naf2.neg()
	}
	return naf1, naf2
}

func (v *glvVectorFr) new(m *Fr) *glvVectorFr {
	// Guide to Pairing Based Cryptography
	// 6.3.2. Decompositions for the k = 12 BLS Family

	// alpha1 = round(x^2 * m  / r)
	alpha1 := alpha1(m)
	// alpha2 = round(m / r)
	alpha2 := alpha2(m)

	z1, z2 := new(Fr), new(Fr)

	// z1 = (x^2 - 1) * round(x^2 * m  / r)
	z1.Mul(alpha1, glvB1)
	// z2 = x^2 * round(m / r)
	z2.Mul(alpha2, glvB2)

	k1, k2 := new(Fr), new(Fr)
	// k1 = m - z1 - alpha2
	k1.Sub(m, z1)
	k1.Sub(k1, alpha2)

	// k2 = z2 - alpha1
	k2.Sub(z2, alpha1)

	if k1.Cmp(r128) == 1 {
		k1.Neg(k1)
		v.neg1 = true
	}
	v.k1 = new(Fr).Set(k1)
	if k2.Cmp(r128) == 1 {
		k2.Neg(k2)
		v.neg2 = true
	}
	v.k2 = new(Fr).Set(k2)
	return v
}

func (v *glvVectorBig) new(m *big.Int) *glvVectorBig {
	// Guide to Pairing Based Cryptography
	// 6.3.2. Decompositions for the k = 12 BLS Family

	// alpha1 = round(x^2 * m  / r)
	alpha1 := new(big.Int).Mul(m, glvQ1Big)
	alpha1.Add(alpha1, halfRBig)
	alpha1.Rsh(alpha1, fourWordBitSize)

	// alpha2 = round(m / r)
	alpha2 := new(big.Int).Mul(m, glvQ2Big)
	alpha2.Add(alpha2, halfRBig)
	alpha2.Rsh(alpha2, fourWordBitSize)

	z1, z2 := new(big.Int), new(big.Int)
	// z1 = (x^2 - 1) * round(x^2 * m  / r)
	z1.Mul(alpha1, glvB1Big).Mod(z1, qBig)
	// z2 = x^2 * round(m / r)
	z2.Mul(alpha2, glvB2Big).Mod(z2, qBig)

	k1, k2 := new(big.Int), new(big.Int)

	// k1 = m - z1 - alpha2
	k1.Sub(m, z1)
	k1.Sub(k1, alpha2)

	// k2 = z2 - alpha1
	k2.Sub(z2, alpha1)

	v.k1 = new(big.Int).Set(k1)
	v.k2 = new(big.Int).Set(k2)
	return v
}

// round(x^2 * m / q)
func alpha1(m *Fr) *Fr {
	a := new(wideFr)
	a.mul(m, glvQ1)
	return a.round()
}

// round(m / q)
func alpha2(m *Fr) *Fr {
	a := new(wideFr)
	a.mul(m, glvQ2)
	return a.round()
}

func phi(a, b *fe) {
	mul(a, b, glvPhi1)
}

func (e *fp2) phi(a, b *fe2) {
	mul(&a[0], &b[0], glvPhi2)
	mul(&a[1], &b[1], glvPhi2)
}

func (g *G1) glvEndomorphism(r, p *PointG1) {
	t := g.Affine(p)
	if g.IsZero(p) {
		r.Zero()
		return
	}
	r[1].set(&t[1])
	phi(&r[0], &t[0])
	r[2].one()
}

func (g *G2) glvEndomorphism(r, p *PointG2) {
	t := g.Affine(p)
	if g.IsZero(p) {
		r.Zero()
		return
	}
	r[1].set(&t[1])
	g.f.phi(&r[0], &t[0])
	r[2].one()
}
