package file

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/mapstructure"
	flag "github.com/spf13/pflag"
	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"

	"github.com/oasisprotocol/deoxysii"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/sakg"
	coreSignature "github.com/oasisprotocol/oasis-core/go/common/crypto/signature"

	"github.com/oasisprotocol/oasis-sdk/cli/config"
	"github.com/oasisprotocol/oasis-sdk/cli/wallet"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/crypto/signature"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/crypto/signature/ed25519"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"
)

const (
	walletKind = "file"

	cfgAlgorithm = "algorithm"
	cfgNumber    = "number"

	algorithmEd25519    = "ed25519"
	algorithmEd25519Raw = "ed25519-raw"

	stateKeySize  = 32
	stateSaltSize = 32
)

type walletConfig struct {
	Algorithm string `mapstructure:"algorithm"`
	Number    uint32 `mapstructure:"number,omitempty"`
}

type secretState struct {
	// Algorithm is the cryptographic algorithm used by the wallet. Note that this may differ from
	// the algorithm set in the wallet's configuration in case the wallet was imported.
	Algorithm string `json:"algorithm"`

	// Data is the secret data used to derive the private key.
	Data string `json:"data"`
}

func (s *secretState) Seal(passphrase string) (*secretStateEnvelope, error) {
	var salt [stateSaltSize]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		return nil, err
	}

	envelope := &secretStateEnvelope{
		Algorithm:  "pbkdf2",
		Salt:       salt[:],
		Iterations: 4096,
	}
	key, err := envelope.deriveKey(passphrase)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	// Initialize a Deoxys-II instance with the provided key and encrypt.
	aead, err := deoxysii.New(key)
	if err != nil {
		return nil, err
	}
	envelope.Data = aead.Seal(nil, envelope.Salt[:aead.NonceSize()], data, nil)

	return envelope, nil
}

type secretStateEnvelope struct {
	Algorithm  string `json:"algorithm"`
	Salt       []byte `json:"salt"`
	Iterations uint32 `json:"iterations"`
	Data       []byte `json:"data"`
}

func (e *secretStateEnvelope) deriveKey(passphrase string) ([]byte, error) {
	switch e.Algorithm {
	case "pbkdf2":
		return pbkdf2.Key([]byte(passphrase), e.Salt, int(e.Iterations), stateKeySize, sha512.New), nil
	default:
		return nil, fmt.Errorf("unsupported key derivation algorithm: %s", e.Algorithm)
	}
}

func (e *secretStateEnvelope) Open(passphrase string) (*secretState, error) {
	// Derive key.
	key, err := e.deriveKey(passphrase)
	if err != nil {
		return nil, err
	}

	// Initialize a Deoxys-II instance with the provided key and decrypt.
	aead, err := deoxysii.New(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, e.Salt[:aead.NonceSize()], e.Data, nil)
	if err != nil {
		return nil, err
	}

	// Deserialize the inner state.
	var state secretState
	if err := json.Unmarshal(pt, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

func getWalletFilename(name string) string {
	return filepath.Join(config.Directory(), fmt.Sprintf("%s.wallet", name))
}

type fileWalletFactory struct {
	flags *flag.FlagSet
}

func (wf *fileWalletFactory) Kind() string {
	return walletKind
}

func (wf *fileWalletFactory) Flags() *flag.FlagSet {
	return wf.flags
}

func (wf *fileWalletFactory) GetConfigFromFlags() (map[string]interface{}, error) {
	cfg := make(map[string]interface{})
	cfg[cfgAlgorithm], _ = wf.flags.GetString(cfgAlgorithm)
	return cfg, nil
}

func (wf *fileWalletFactory) RequiresPassphrase() bool {
	// A file-backed wallet always requires a passphrase.
	return true
}

func (wf *fileWalletFactory) unmarshalConfig(raw map[string]interface{}) (*walletConfig, error) {
	if raw == nil {
		return nil, fmt.Errorf("missing configuration")
	}

	var cfg walletConfig
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (wf *fileWalletFactory) Create(name string, passphrase string, rawCfg map[string]interface{}) (wallet.Wallet, error) {
	cfg, err := wf.unmarshalConfig(rawCfg)
	if err != nil {
		return nil, err
	}

	// Generate entropy.
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	state := &secretState{
		Algorithm: cfg.Algorithm,
		Data:      mnemonic,
	}

	// Seal state.
	envelope, err := state.Seal(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to seal state: %w", err)
	}

	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	if err := ioutil.WriteFile(getWalletFilename(name), raw, 0o600); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	// Create a proper wallet based on the chosen algorithm.
	return newWallet(state, cfg)
}

func (wf *fileWalletFactory) Load(name string, passphrase string, rawCfg map[string]interface{}) (wallet.Wallet, error) {
	cfg, err := wf.unmarshalConfig(rawCfg)
	if err != nil {
		return nil, err
	}

	// Load state from encrypted file.
	raw, err := ioutil.ReadFile(getWalletFilename(name))
	if err != nil {
		return nil, fmt.Errorf("failed to load wallet state: %w", err)
	}

	var envelope secretStateEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("failed to load wallet state: %w", err)
	}

	var state *secretState
	if state, err = envelope.Open(passphrase); err != nil {
		return nil, fmt.Errorf("failed to open wallet state (maybe incorrect passphrase?)")
	}

	return newWallet(state, cfg)
}

func (wf *fileWalletFactory) Remove(name string, rawCfg map[string]interface{}) error {
	return os.Remove(getWalletFilename(name))
}

func (wf *fileWalletFactory) Import(name string, passphrase string, rawCfg map[string]interface{}, src *wallet.ImportSource) (wallet.Wallet, error) {
	cfg, err := wf.unmarshalConfig(rawCfg)
	if err != nil {
		return nil, err
	}

	var state secretState
	switch src.Kind {
	case wallet.ImportKindMnemonic:
		// Import a mnemonic.
		state.Algorithm = cfg.Algorithm
		state.Data = src.Data
	case wallet.ImportKindPrivateKey:
		// Import a private key. This requires us to change the algorithm to the raw variant.
		switch cfg.Algorithm {
		case algorithmEd25519:
			state.Algorithm = algorithmEd25519Raw
			state.Data = src.Data
		default:
			return nil, fmt.Errorf("unsupported private key import algorithm: %s", cfg.Algorithm)
		}
	default:
		return nil, fmt.Errorf("unsupported import kind: %s", src.Kind)
	}

	// Seal state.
	envelope, err := state.Seal(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to seal state: %w", err)
	}

	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	if err := ioutil.WriteFile(getWalletFilename(name), raw, 0o600); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	// Create a proper wallet based on the chosen algorithm.
	return newWallet(&state, cfg)
}

type fileWallet struct {
	cfg    *walletConfig
	state  *secretState
	signer signature.Signer
}

func newWallet(state *secretState, cfg *walletConfig) (wallet.Wallet, error) {
	switch state.Algorithm {
	case algorithmEd25519:
		// For Ed25519 use the ADR 0008 derivation scheme.
		signer, _, err := sakg.GetAccountSigner(state.Data, "", cfg.Number)
		if err != nil {
			return nil, fmt.Errorf("failed to derive signer: %w", err)
		}

		return &fileWallet{
			cfg:    cfg,
			state:  state,
			signer: ed25519.WrapSigner(signer),
		}, nil
	case algorithmEd25519Raw:
		// For Ed25519-Raw use the raw private key.
		var signer ed25519rawSigner
		if err := signer.unmarshalBase64(state.Data); err != nil {
			return nil, fmt.Errorf("failed to initialize signer: %w", err)
		}

		return &fileWallet{
			cfg:    cfg,
			state:  state,
			signer: ed25519.WrapSigner(&signer),
		}, nil
	default:
		return nil, fmt.Errorf("algorithm '%s' not supported", state.Algorithm)
	}
}

func (w *fileWallet) ConsensusSigner() coreSignature.Signer {
	type wrappedSigner interface {
		Unwrap() coreSignature.Signer
	}

	if ws, ok := w.signer.(wrappedSigner); ok {
		return ws.Unwrap()
	}
	return nil
}

func (w *fileWallet) Signer() signature.Signer {
	return w.signer
}

func (w *fileWallet) Address() types.Address {
	return types.NewAddress(w.SignatureAddressSpec())
}

func (w *fileWallet) SignatureAddressSpec() types.SignatureAddressSpec {
	switch w.cfg.Algorithm {
	case algorithmEd25519:
		return types.NewSignatureAddressSpecEd25519(w.Signer().Public().(ed25519.PublicKey))
	default:
		return types.SignatureAddressSpec{}
	}
}

func (w *fileWallet) UnsafeExport() string {
	return w.state.Data
}

func init() {
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.String(cfgAlgorithm, algorithmEd25519, "Cryptographic algorithm to use for this wallet")

	wallet.Register(&fileWalletFactory{
		flags: flags,
	})
}
