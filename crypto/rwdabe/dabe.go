package rwdabe

import (
	//"basics/crypto/bn128"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	"strings"
	"time"
)

// MAABE represents a MAABE scheme.
type MAABE struct {
	P  *big.Int
	G1 *bn128.G1
	G2 *bn128.G2
	Gt *bn128.GT
}

// NewMAABE configures a new instance of the scheme.
func NewMAABE() *MAABE {
	gen1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	gen2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	return &MAABE{
		P:  bn128.Order,
		G1: gen1,
		G2: gen2,
		Gt: bn128.Pair(gen1, gen2),
	}
}

func KDF(gt *bn128.GT) []byte {
	hash := sha256.New()
	hash.Write([]byte(gt.String()))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	password := hashBytes[0:16]
	salt := hashBytes[16:]
	fmt.Println(hashString, hex.EncodeToString(password), hex.EncodeToString(salt))
	key := pbkdf2.Key(password, salt, 10000, 512, sha256.New)
	return key
}
func xorEncryptDecrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// MAABEPubKey represents a public key for an authority.
type MAABEPubKey struct {
	//Attribs    []string
	ID         string
	EggToAlpha *bn128.GT
	GToY       *bn128.G2
}

// MAABESecKey represents a secret key for an authority.
type MAABESecKey struct {
	//Attribs []string
	Alpha *big.Int
	Y     *big.Int
}

// MAABEAuth represents an authority in the MAABE scheme.
type MAABEAuth struct {
	//ID    string
	Maabe *MAABE
	Pk    *MAABEPubKey
	Sk    *MAABESecKey
}

// NewMAABEAuth configures a new instance of an authority and generates its
// public and secret keys for the given set of attributes. In case of a failed
// procedure an error is returned.
func (a *MAABE) NewMAABEAuth(id string) (*MAABEAuth, error) {
	v, _ := data.NewRandomVector(2, sample.NewUniform(a.P))
	alpha := v[0]
	y := v[1]
	sk := &MAABESecKey{Alpha: alpha, Y: y}
	pk := &MAABEPubKey{ID: id, EggToAlpha: new(bn128.GT).ScalarMult(a.Gt, alpha), GToY: new(bn128.G2).ScalarMult(a.G2, y)}
	return &MAABEAuth{
		//ID:    id,
		Maabe: a,
		Pk:    pk,
		Sk:    sk,
	}, nil
}

// MAABECipher represents a ciphertext of a MAABE scheme.
type MAABECipher struct {
	C0         *bn128.GT
	C1x        map[string]*bn128.GT
	C2x        map[string]*bn128.G2
	C3x        map[string]*bn128.G2
	C4x        map[string]*bn128.G1
	Msp        *lib.MSP
	ciphertext []byte // symmetric encryption of the string message
}

func (a *MAABECipher) String() string {
	res := ""
	res += a.C0.String()
	for one := range a.C1x {
		res += a.C1x[one].String()
		res += a.C2x[one].String()
		res += a.C3x[one].String()
		res += a.C4x[one].String()
	}

	return res
}

func (a *MAABE) Encrypt(msg string, msp *lib.MSP, pks []*MAABEPubKey) (*MAABECipher, error) {
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	attribs := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attribs[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attribs[i] = true
	}
	if len(msg) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}
	// msg is encrypted with AES-CBC with a random key that is encrypted with
	// MA-ABE
	// generate secret key
	_, symKey, err := bn128.RandomGT(rand.Reader)
	fmt.Println(symKey)
	if err != nil {
		return nil, err
	}
	ciphertext := xorEncryptDecrypt([]byte(msg), KDF(symKey))

	// now encrypt symKey with MA-ABE
	// rand generator
	sampler := sample.NewUniform(a.P)
	// pick random vector v with random s as first element
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	s := v[0]
	if err != nil {
		return nil, err
	}
	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}
	lambda := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		lambda[at] = lambdaI[i]
	}
	// pick random vector w with 0 as first element
	w, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	w[0] = big.NewInt(0)
	omegaI, err := msp.Mat.MulVec(w)
	if err != nil {
		return nil, err
	}
	if len(omegaI) != mspRows {
		return nil, fmt.Errorf("wrong omega len")
	}
	omega := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		omega[at] = omegaI[i]
	}
	startts := time.Now().UnixNano() / 1e3
	// calculate ciphertext
	c0 := new(bn128.GT).Add(symKey, new(bn128.GT).ScalarMult(a.Gt, s))
	c1 := make(map[string]*bn128.GT)
	c2 := make(map[string]*bn128.G2)
	c3 := make(map[string]*bn128.G2)
	c4 := make(map[string]*bn128.G1)
	// get randomness
	rI, err := data.NewRandomVector(mspRows, sampler)
	r := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		r[at] = rI[i]
	}
	if err != nil {
		return nil, err
	}
	for _, at := range msp.RowToAttrib {
		// find the correct pubkey
		foundPK := false
		for _, pk := range pks {
			if strings.Split(at, ":")[0] == pk.ID {
				// CAREFUL: negative numbers do not play well with ScalarMult
				signLambda := lambda[at].Cmp(big.NewInt(0))
				signOmega := omega[at].Cmp(big.NewInt(0))
				var tmpLambda *bn128.GT
				var tmpOmega *bn128.G2
				if signLambda >= 0 {
					tmpLambda = new(bn128.GT).ScalarMult(a.Gt, lambda[at])
				} else {
					tmpLambda = new(bn128.GT).ScalarMult(new(bn128.GT).Neg(a.Gt), new(big.Int).Abs(lambda[at]))
				}
				if signOmega >= 0 {
					tmpOmega = new(bn128.G2).ScalarMult(a.G2, omega[at])
				} else {
					tmpOmega = new(bn128.G2).ScalarMult(new(bn128.G2).Neg(a.G2), new(big.Int).Abs(omega[at]))
				}
				c1[at] = new(bn128.GT).Add(tmpLambda, new(bn128.GT).ScalarMult(pk.EggToAlpha, r[at]))
				c2[at] = new(bn128.G2).ScalarMult(new(bn128.G2).Neg(a.G2), r[at]) //new(bn128.G2).ScalarMult(a.G2, r[at])
				c3[at] = new(bn128.G2).Add(new(bn128.G2).ScalarMult(pk.GToY, r[at]), tmpOmega)
				F_delta, _ := bn128.HashG1(at)
				c4[at] = new(bn128.G1).ScalarMult(F_delta, r[at])
				foundPK = true
				break
			}
		}
		if !foundPK {
			return nil, fmt.Errorf("attribute not found in any pubkey")
		}
	}
	endts := time.Now().UnixNano() / 1e3
	if startts == endts {
		fmt.Printf("encrypt time cost: %v μs\n", (endts - startts))
	}

	return &MAABECipher{
		C0:         c0,
		C1x:        c1,
		C2x:        c2,
		C3x:        c3,
		C4x:        c4,
		Msp:        msp,
		ciphertext: ciphertext,
	}, nil
}

// MAABEKey represents a key corresponding to an attribute possessed by an
// entity. They are issued by the relevant authorities and are used for
// decryption in a MAABE scheme.
type MAABEKey struct {
	Gid      string
	Attrib   string
	Key      *bn128.G1
	KeyPrime *bn128.G2
}

func (a *MAABEKey) String() string {
	res := ""
	res += a.Gid
	res += a.Attrib
	res += a.Key.String()
	return res
}

// GenerateAttribKeys generates a list of attribute keys for the given user
// (represented by its Global ID) that possesses the given list of attributes.
// In case of a failed procedure an error is returned. The relevant authority
// has to check that the entity actually possesses the attributes via some
// other channel.
func (auth *MAABEAuth) GenerateAttribKeys(gid string, attribs []string) ([]*MAABEKey, error) {
	// sanity checks
	if len(gid) == 0 {
		return nil, fmt.Errorf("GID cannot be empty")
	}
	if len(attribs) == 0 {
		return nil, fmt.Errorf("attribute cannot be empty")
	}
	if auth.Maabe == nil {
		return nil, fmt.Errorf("ma-abe scheme cannot be nil")
	}
	hash, err := bn128.HashG1(gid)
	if err != nil {
		return nil, err
	}
	ks := make([]*MAABEKey, len(attribs))
	for i, at := range attribs {
		var k *bn128.G1
		var kp *bn128.G2
		if auth.Sk.Alpha != nil && auth.Sk.Y != nil {
			F_delta, _ := bn128.HashG1(at)
			k = new(bn128.G1).Add(new(bn128.G1).ScalarMult(auth.Maabe.G1, auth.Sk.Alpha), new(bn128.G1).ScalarMult(hash, auth.Sk.Y))
			v, _ := data.NewRandomVector(1, sample.NewUniform(auth.Maabe.P))
			k = new(bn128.G1).Add(k, new(bn128.G1).ScalarMult(F_delta, v[0]))
			kp = new(bn128.G2).ScalarMult(auth.Maabe.G2, v[0])
			ks[i] = &MAABEKey{
				Gid:      gid,
				Attrib:   at,
				Key:      k,
				KeyPrime: kp,
			}
		} else {
			return nil, fmt.Errorf("attribute not found in secret key")
		}
	}
	return ks, nil
}

// Decrypt takes a ciphertext in a MAABE scheme and a set of attribute keys
// belonging to the same entity, and attempts to decrypt the cipher. This is
// possible only if the set of possessed attributes/keys suffices the
// decryption policy of the ciphertext. In case this is not possible or
// something goes wrong an error is returned.
func (a *MAABE) Decrypt(ct *MAABECipher, ks []*MAABEKey) (string, error) {
	// sanity checks
	if len(ks) == 0 {
		return "", fmt.Errorf("empty set of attribute keys")
	}
	gid := ks[0].Gid
	for _, k := range ks {
		if k.Gid != gid {
			return "", fmt.Errorf("not all GIDs are the same")
		}
	}
	// get hashed GID
	hash, err := bn128.HashG1(gid)
	if err != nil {
		return "", err
	}
	// find out which attributes are valid and extract them
	goodMatRows := make([]data.Vector, 0)
	goodAttribs := make([]string, 0)
	aToK := make(map[string]*MAABEKey)
	for _, k := range ks {
		aToK[k.Attrib] = k
	}
	for i, at := range ct.Msp.RowToAttrib {
		if aToK[at] != nil {
			goodMatRows = append(goodMatRows, ct.Msp.Mat[i])
			goodAttribs = append(goodAttribs, at)
		}
	}
	goodMat, err := data.NewMatrix(goodMatRows)
	if err != nil {
		return "", err
	}
	//choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
	// if they don't exist, keys are not ok
	goodCols := goodMat.Cols()
	if goodCols == 0 {
		return "", fmt.Errorf("no good matrix columns, most likely the keys contain no valid attribute")
	}
	one := data.NewConstantVector(goodCols, big.NewInt(0))
	one[0] = big.NewInt(1)
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, a.P)
	if err != nil {
		return "", err
	}
	cx := make(map[string]*big.Int)
	for i, at := range goodAttribs {
		cx[at] = c[i]
	}
	// compute intermediate values
	eggLambda := make(map[string]*bn128.GT)
	for _, at := range goodAttribs {
		if ct.C1x[at] != nil && ct.C2x[at] != nil && ct.C3x[at] != nil && ct.C4x[at] != nil {
			num := new(bn128.GT).Add(ct.C1x[at], bn128.Pair(aToK[at].Key, ct.C2x[at]))
			num = new(bn128.GT).Add(num, bn128.Pair(hash, ct.C3x[at]))
			num = new(bn128.GT).Add(num, bn128.Pair(ct.C4x[at], aToK[at].KeyPrime))
			eggLambda[at] = num
		} else {
			fmt.Println(ct.C1x[at] != nil, ct.C2x[at] != nil, ct.C3x[at] != nil, ct.C4x[at] != nil)
			return "", fmt.Errorf("attribute %s not in ciphertext dicts", at)
		}
	}
	eggs := new(bn128.GT).ScalarBaseMult(big.NewInt(0))
	for _, at := range goodAttribs {
		if eggLambda[at] != nil {
			sign := cx[at].Cmp(big.NewInt(0))
			if sign == 1 {
				eggs.Add(eggs, new(bn128.GT).ScalarMult(eggLambda[at], cx[at]))
			} else if sign == -1 {
				eggs.Add(eggs, new(bn128.GT).ScalarMult(new(bn128.GT).Neg(eggLambda[at]), new(big.Int).Abs(cx[at])))
			}
		} else {
			return "", fmt.Errorf("missing intermediate result")
		}
	}
	// calculate key for symmetric encryption
	symKey := new(bn128.GT).Add(ct.C0, new(bn128.GT).Neg(eggs))
	msg := xorEncryptDecrypt(ct.ciphertext, KDF(symKey))
	//fmt.Println(string(msg))
	return string(msg), nil
}
