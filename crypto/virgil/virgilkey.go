package virgil

import (
	"bytes"

	vcrypto "github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	aminoCrypto "github.com/tendermint/tendermint/crypto/encoding/amino"
	"golang.org/x/crypto/ripemd160"
)

var (
	cdc = amino.NewCodec()

	_ crypto.PubKey  = &VirgilPublicKey{}
	_ crypto.PrivKey = &VirgilPrivateKey{}
)

func init() {
	aminoCrypto.RegisterKeyType(VirgilPublicKey{}, "virgil/PublicKey")
	aminoCrypto.RegisterKeyType(&VirgilPrivateKey{}, "virgil/PrivateKey")

	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)

	RegisterAmino(cdc)
}

// RegisterAmino registers all go-crypto related types in the given (amino) codec.
func RegisterAmino(cdc *amino.Codec) {
	cdc.RegisterConcrete(&VirgilPublicKey{}, "virgil/PublicKey", nil)
	cdc.RegisterConcrete(&VirgilPrivateKey{}, "virgil/PrivateKey", nil)
}

func NewVirgilPublicKey(k vcrypto.PublicKey, c vcrypto.Crypto) *VirgilPublicKey {
	return &VirgilPublicKey{
		key:    k,
		crypto: c,
	}
}

type VirgilPublicKey struct {
	key    vcrypto.PublicKey
	crypto vcrypto.Crypto
}

func (k *VirgilPublicKey) Address() crypto.Address {
	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(k.key.Identifier()) // does not error
	return hasherRIPEMD160.Sum(nil)
}

func (k *VirgilPublicKey) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(k)
}

func (k *VirgilPublicKey) VerifyBytes(msg []byte, sig []byte) bool {
	err := k.crypto.VerifySignature(msg, sig, k.key)
	return err == nil
}

func (k *VirgilPublicKey) Equals(pk crypto.PubKey) bool {
	return bytes.Equal(k.Address(), pk.Address())
}

func (k VirgilPublicKey) MarshalAmino() ([]byte, error) {
	exp, err := k.crypto.ExportPublicKey(k.key)
	if err != nil {
		return nil, err
	}
	return exp, nil
}

func (k *VirgilPublicKey) UnmarshalAmino(data []byte) error {
	var crp vcrypto.Crypto
	pk, err := crp.ImportPublicKey(data)
	if err != nil {
		return err
	}
	*k = VirgilPublicKey{
		key:    pk,
		crypto: crp,
	}
	return nil
}

func NewVirgilPrivateKey(k vcrypto.PrivateKey, c vcrypto.Crypto) *VirgilPrivateKey {
	return &VirgilPrivateKey{
		key:    k,
		crypto: c,
	}
}

type VirgilPrivateKey struct {
	key    vcrypto.PrivateKey
	crypto vcrypto.Crypto
}

func (k *VirgilPrivateKey) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(k)
}

func (k *VirgilPrivateKey) PubKey() crypto.PubKey {
	return &VirgilPublicKey{
		key:    k.key.PublicKey(),
		crypto: k.crypto,
	}
}

func (k *VirgilPrivateKey) Sign(msg []byte) ([]byte, error) {
	return k.crypto.Sign(msg, k.key)
}

func (k *VirgilPrivateKey) Equals(privateKey crypto.PrivKey) bool {
	sk, ok := privateKey.(*VirgilPrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(k.key.Identifier(), sk.key.Identifier())
}

func (k VirgilPrivateKey) MarshalAmino() ([]byte, error) {
	exp, err := k.crypto.ExportPrivateKey(k.key)
	if err != nil {
		return nil, err
	}
	return exp, nil
}

func (k *VirgilPrivateKey) UnmarshalAmino(data []byte) error {
	var crp vcrypto.Crypto
	pk, err := crp.ImportPrivateKey(data)
	if err != nil {
		return err
	}
	*k = VirgilPrivateKey{
		key:    pk,
		crypto: crp,
	}
	return nil
}
