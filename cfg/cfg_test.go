package cfg

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

const (
	configFromWebEncrypted  = "testdata/NETGEAR_Orbi.cfg"
	configFromWebDecrypted  = "testdata/NETGEAR_Orbi.cfg.json"
	configFromSOAPEncrypted = "testdata/soap_config.cfg"
	configFromSOAPDecrypted = "testdata/soap_config.json"
	magic                   = 0x20131224
)

func TestJSONWeb(t *testing.T) {
	testJSON(t, configFromWebEncrypted, configFromWebDecrypted)
}

func TestJSONSOAP(t *testing.T) {
	testJSON(t, configFromSOAPEncrypted, configFromSOAPDecrypted)
}

func testJSON(t *testing.T, encryptedFile, decryptedFile string) {
	// Decrypt encrypted config into raw bytes
	_, rawConfig := decryptFile(t, encryptedFile, false)

	// Read already-decrypted, JSON-formatted config
	expectedJsonConfig, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("read json config: %v", err)
	}

	// Convert JSON config to raw config bytes
	expectedRawConfig, err := FromJSON(expectedJsonConfig)
	if err != nil {
		t.Fatalf("from json: %v", err)
	}

	// Compare the two raw configs
	if !bytes.Equal(rawConfig, expectedRawConfig) {
		t.Fatalf("raw configs not equal")
	}

	// Compare the two as JSON
	jsonConfig, err := ToJSON(rawConfig)
	if err != nil {
		t.Fatalf("to json: %v", err)
	}
	if !bytes.Equal(jsonConfig, expectedJsonConfig) {
		t.Fatalf("json configs not equal")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Read decrypted, JSON-formatted config
	jsonConfig, err := os.ReadFile(configFromWebDecrypted)
	if err != nil {
		t.Fatalf("read json config: %v", err)
	}

	// Load JSON data into a map
	jsonConfigMap := orderedmap.New[string, string]()
	if err = jsonConfigMap.UnmarshalJSON(jsonConfig); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	// Add a new entry and marshal back into JSON
	jsonConfigMap.Set("my-new-key", "foobar")
	jsonConfig, err = jsonConfigMap.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	// Convert JSON to raw config and encrypt it
	rawConfig, err := FromJSON(jsonConfig)
	if err != nil {
		t.Fatalf("from json: %v", err)
	}
	encryptedConfig := Encrypt(rawConfig, magic)

	// Decrypt the modified config back into JSON and load it into a map
	_, rawConfig, err = Decrypt(encryptedConfig, false)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	jsonConfig, err = ToJSON(rawConfig)
	if err != nil {
		t.Fatalf("to json: %v", err)
	}
	newJsonConfigMap := orderedmap.New[string, string]()
	if err = newJsonConfigMap.UnmarshalJSON(jsonConfig); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	// Verify that the new entry is present
	if val, _ := newJsonConfigMap.Get("my-new-key"); val != "foobar" {
		t.Fatalf("inserted key not present")
	}
}

func TestChecksum(t *testing.T) {
	encryptedConfig, err := os.ReadFile(configFromSOAPEncrypted)
	if err != nil {
		t.Fatalf("read encrypted config: %v", err)
	}

	// Make the checksum invalid and try to decrypt
	binary.LittleEndian.PutUint32(encryptedConfig[8:], 0xeeeeeeee)
	_, _, err = Decrypt(encryptedConfig, false)
	assert.EqualError(t, err, ErrorInvalidChecksum)

	// Verify that decryption works with `ignoreChecksum`
	_, rawConfig, err := Decrypt(encryptedConfig, true)
	assert.NoError(t, err)

	// Calculate and restore the proper checksum
	binary.LittleEndian.PutUint32(encryptedConfig[8:], calcChecksum(rawConfig))
	_, _, err = Decrypt(encryptedConfig, false)
	assert.NoError(t, err)
}

func decryptFile(t *testing.T, encryptedFile string, ignoreChecksum bool) (*Header, []byte) {
	encryptedConfig, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("read encrypted config: %v", err)
	}

	header, rawConfig, err := Decrypt(encryptedConfig, ignoreChecksum)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return header, rawConfig
}
