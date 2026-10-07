package sync

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/encoding/protowire"
)

var Debug bool

var Silent bool

func DebugPrint(in string) {
	if Debug {
		fmt.Println("[!] DEBUG: " + in)
	}
}

func GzipEncode(inbytes []byte) []byte {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	_, err := gzipWriter.Write(inbytes)
	if err != nil {
		panic(err)
	}
	gzipWriter.Close()
	return buf.Bytes()
}

func DoSyncHTTPRequest(body []byte, url string, accessToken string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authorization", "aadv2 "+accessToken)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	DebugPrint("Status:" + resp.Status)
	if strings.Compare(resp.Status, "200 OK") != 0 {
		return nil, errors.New("Invalid Server Response: " + resp.Status)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	DebugPrint(string(b))
	return b, nil
}

func DoUseLicenseHTTPRequest(body []byte, url string, accessToken string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authorization", "bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ms-Rms-Platform-Id", "AppName=Microsoft Edge (stable) (RustyMIP=0);AppVersion=144.0.3719.115;DevicePlatform=WindowsStore;SDKVersion=4.3;UniqueId=ecd6b820-32c2-49b6-98a6-444530e5a77a;OsName=win;OsVersion=10-0-19045;MipVersion=1.14.146;")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

const CBC4kBlockSize = 4096

func DeriveCBC4kIV(key []byte, blockCounter uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counterBlock := make([]byte, aes.BlockSize)
	binary.LittleEndian.PutUint64(counterBlock[:8], blockCounter)
	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, counterBlock)
	return iv, nil
}

func DecryptCBC4k(b64key string, ciphertextb64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return "", errors.New("use license key is not valid base64: " + err.Error())
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextb64)
	if err != nil {
		return "", errors.New("publishing license data is not valid base64: " + err.Error())
	}
	if len(ciphertext) > CBC4kBlockSize {

		return "", errors.New("publishing license data is larger than one CBC4K block (" +
			strconv.Itoa(len(ciphertext)) + " bytes) -- multi-block decryption is not implemented")
	}
	iv, err := DeriveCBC4kIV(key, 0)
	if err != nil {
		return "", err
	}
	plaintext, err := decryptAESCBC256(key, iv, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func decryptAESCBC256(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	paddingLen := int(data[len(data)-1])

	if paddingLen == 0 || paddingLen > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}

	for i := 0; i < paddingLen; i++ {
		if data[len(data)-1-i] != byte(paddingLen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-paddingLen], nil
}

func GetDecryptionKeyFromDeriviationKey(deriviationPassword string) []byte {
	password := []byte(deriviationPassword)

	salt := []byte{
		0xc7, 0xca, 0xfb, 0x23,
		0xec, 0x2a, 0x9d, 0x4c,
		0x03, 0x5a, 0x90, 0xae,
		0xed, 0x8b, 0xa4, 0x98,
	}
	iterations := 1003
	keyLen := 16

	key := pbkdf2.Key(password, salt, iterations, keyLen, sha1.New)
	return key
}

func GetMacKeyFromDeriviationKey(deriviationPassword string) []byte {
	password := []byte(deriviationPassword)
	salt := []byte{
		0xc7, 0xca, 0xfb, 0x23,
		0xec, 0x2a, 0x9d, 0x4c,
		0x03, 0x5a, 0x90, 0xae,
		0xed, 0x8b, 0xa4, 0x98,
	}
	iterations := 1004
	keyLen := 16

	key := pbkdf2.Key(password, salt, iterations, keyLen, sha1.New)
	return key
}

func CreateHMACSHA256(mackey, ciphertext []byte) []byte {
	mac := hmac.New(sha256.New, mackey)
	mac.Write(ciphertext)
	computedMAC := mac.Sum(nil)
	return computedMAC
}

func DecryptSyncData(b64encciphertext string, key []byte) (string, error) {

	ct, err := base64.StdEncoding.DecodeString(b64encciphertext)
	if err != nil {
		return "", err
	}
	iv := ct[:16]
	ciphertext := ct[16 : len(ct)-32]
	pt, err := AES128CBCDecrypt(key, iv, ciphertext)
	if err != nil {
		return "", err
	}

	return string(pt), nil
}

func AES128CBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {

	if len(key) != 16 {
		return nil, errors.New("key must be 16 bytes (AES-128)")
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("iv must be 16 bytes")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext not multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

func EncryptMessageData(key, mackey, plaintext []byte) ([]byte, error) {
	iv := []byte{
		0x75, 0x12, 0x6b, 0xe2,
		0x52, 0x81, 0x27, 0x33,
		0x96, 0x19, 0x69, 0x74,
		0x1b, 0xee, 0x44, 0x2d,
	}
	ct, err := AES128CBCEncrypt(key, iv, plaintext)
	if err != nil {
		return []byte{}, err
	}
	mac := CreateHMACSHA256(mackey, ct)
	out := []byte{}
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, mac...)
	return out, nil
}

func AES128CBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {

	if len(key) != 16 {
		return nil, errors.New("key must be 16 bytes (AES-128)")
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("iv must be 16 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded, err := pkcs7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}

	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...), nil
}

func ArbitiaryProtoBufParser(data []byte, indent int) {
	if !Debug {
		return
	}
	offset := 0

	for offset < len(data) {

		key, n := protowire.ConsumeVarint(data[offset:])
		if n < 0 {
			return
		}
		offset += n

		fieldNum := key >> 3
		wireType := protowire.Type(key & 0x7)

		printIndent(indent)
		fmt.Printf("%d", fieldNum)

		switch wireType {

		case protowire.VarintType:
			val, n := protowire.ConsumeVarint(data[offset:])
			if n < 0 {
				return
			}
			offset += n
			fmt.Printf(": %d\n", val)

		case protowire.Fixed32Type:
			val, n := protowire.ConsumeFixed32(data[offset:])
			if n < 0 {
				return
			}
			offset += n
			fmt.Printf(": %d\n", val)

		case protowire.Fixed64Type:
			val, n := protowire.ConsumeFixed64(data[offset:])
			if n < 0 {
				return
			}
			offset += n
			fmt.Printf(": %d\n", val)

		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data[offset:])
			if n < 0 {
				return
			}
			offset += n

			if looksLikeProto(val) {
				fmt.Printf(" {\n")
				ArbitiaryProtoBufParser(val, indent+1)
				printIndent(indent)
				fmt.Printf("}\n")
			} else if utf8.Valid(val) {
				fmt.Printf(": \"%s\"\n", val)
			} else {
				fmt.Printf(": \"%s\"\n", base64.StdEncoding.EncodeToString(val))
			}

		default:
			fmt.Printf(": [unknown wire type]\n")
			return
		}
	}
}

func looksLikeProto(data []byte) bool {
	offset := 0

	for offset < len(data) {
		key, n := protowire.ConsumeVarint(data[offset:])
		if n <= 0 {
			return false
		}
		offset += n

		fieldNum := key >> 3
		wireType := protowire.Type(key & 0x7)

		if fieldNum == 0 {
			return false
		}

		switch wireType {
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(data[offset:])
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(data[offset:])
		case protowire.Fixed64Type:
			_, n = protowire.ConsumeFixed64(data[offset:])
		case protowire.BytesType:
			_, n = protowire.ConsumeBytes(data[offset:])
		default:
			return false
		}

		if n <= 0 {
			return false
		}
		offset += n
	}

	return true
}

func printIndent(n int) {
	for i := 0; i < n; i++ {
		fmt.Print("  ")
	}
}

func ParseTimeStamp(ts int64) string {
	t := time.UnixMilli(ts).UTC().String()
	return t

}

func RandomGUID() (string, error) {
	b := make([]byte, 16)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	guid := fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)

	return guid, nil
}
