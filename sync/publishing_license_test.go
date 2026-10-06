package sync

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func mipEncryptCBC4k(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	counterBlock := make([]byte, aes.BlockSize)
	binary.LittleEndian.PutUint64(counterBlock[:8], 0)
	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, counterBlock)

	pt := []byte(plaintext)
	padLen := aes.BlockSize - len(pt)%aes.BlockSize
	pt = append(pt, bytes.Repeat([]byte{byte(padLen)}, padLen)...)

	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pt)
	return base64.StdEncoding.EncodeToString(ct)
}

const testDerivationKey = "1E4GxVR8Xwud70clYMlMNmgddpTAzM/rU2iaxX/ppmo="

var testPayload = `{"creation_time":1752796800.0,"new_key":"` + testDerivationKey + `"}`

func TestDeriveCBC4kIVIsNotZero(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	iv, err := DeriveCBC4kIV(key, 0)
	if err != nil {
		t.Fatalf("DeriveCBC4kIV: %v", err)
	}
	if len(iv) != aes.BlockSize {
		t.Fatalf("IV length = %d, want %d", len(iv), aes.BlockSize)
	}
	if bytes.Equal(iv, make([]byte, aes.BlockSize)) {
		t.Fatal("derived IV is all zeros; the derivation is wrong")
	}

	iv1, err := DeriveCBC4kIV(key, 1)
	if err != nil {
		t.Fatalf("DeriveCBC4kIV(1): %v", err)
	}
	if bytes.Equal(iv, iv1) {
		t.Fatal("block 0 and block 1 derived the same IV")
	}
}

func TestDecryptCBC4kRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	b64key := base64.StdEncoding.EncodeToString(key)
	data := mipEncryptCBC4k(t, key, testPayload)

	pt, err := DecryptCBC4k(b64key, data)
	if err != nil {
		t.Fatalf("DecryptCBC4k: %v", err)
	}
	if pt != testPayload {
		t.Fatalf("plaintext mismatch:\n got %q\nwant %q", pt, testPayload)
	}

	got, err := ParseNewKeyResponse(pt)
	if err != nil {
		t.Fatalf("ParseNewKeyResponse: %v", err)
	}
	if got != testDerivationKey {
		t.Fatalf("new_key = %q, want %q", got, testDerivationKey)
	}
}

func TestZeroIVCorruptsExactlyOneBlock(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	data := mipEncryptCBC4k(t, key, testPayload)
	ct, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}

	legacy, err := decryptAESCBC256(key, make([]byte, aes.BlockSize), ct)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if string(legacy) == testPayload {
		t.Fatal("zero IV produced the correct plaintext; the IV must not matter, which contradicts CBC")
	}
	if string(legacy[aes.BlockSize:]) != testPayload[aes.BlockSize:] {
		t.Fatal("zero IV corrupted more than the first block")
	}
	if len(`{"creation_time"`) != aes.BlockSize {
		t.Fatal("JSON prefix is no longer exactly one AES block")
	}

	got, err := ParseNewKeyResponse(string(legacy))
	if err != nil {
		t.Fatalf("ParseNewKeyResponse on damaged plaintext: %v", err)
	}
	if got != testDerivationKey {
		t.Fatalf("salvaged new_key = %q, want %q", got, testDerivationKey)
	}
}

func TestParseNewKeyResponseIgnoresFieldOrder(t *testing.T) {
	payload := `{"new_key":"` + testDerivationKey + `","creation_time":1752796800.0}`
	got, err := ParseNewKeyResponse(payload)
	if err != nil {
		t.Fatalf("ParseNewKeyResponse: %v", err)
	}
	if got != testDerivationKey {
		t.Fatalf("new_key = %q, want %q", got, testDerivationKey)
	}
}

func TestParseNewKeyResponseErrors(t *testing.T) {
	if _, err := ParseNewKeyResponse(`{"creation_time":1.0}`); err == nil {
		t.Fatal("expected an error for a payload with no new_key")
	}
	if _, err := ParseNewKeyResponse(""); err == nil {
		t.Fatal("expected an error for an empty payload")
	}
}
