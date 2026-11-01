package wire

// VaultObject is opaque ciphertext. Its digest is an immutable object ID;
// metadata and the decryption key exist only inside the signed vault catalog.
type VaultObject struct {
	Blob []byte `json:"blob"`
}
