package cfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var devices = []string{"RBR50", "RBR760"}

const (
	testDataDir                = "testdata"
	encryptedConfigFile        = "encrypted.cfg"
	decryptedConfigFile        = "decrypted.json"
	decryptedConfigFileRaw     = "decrypted_raw.json"
	encryptedConfigFileSoap    = "encrypted_soap.cfg"
	decryptedConfigFileSoap    = "decrypted_soap.json"
	decryptedConfigFileSoapRaw = "decrypted_soap_raw.json"
)

func TestDecrypt(t *testing.T) {
	for _, d := range devices {
		testDecrypt(t, filepath.Join(testDataDir, d, encryptedConfigFile),
			filepath.Join(testDataDir, d, decryptedConfigFile),
			filepath.Join(testDataDir, d, decryptedConfigFileRaw))
	}
}

func TestDecryptSoap(t *testing.T) {
	// Only RBR50 for now
	// TODO: add SOAP test cases for other devices
	testDecrypt(t, filepath.Join(testDataDir, devices[0], encryptedConfigFileSoap),
		filepath.Join(testDataDir, devices[0], decryptedConfigFileSoap),
		filepath.Join(testDataDir, devices[0], decryptedConfigFileSoapRaw))
}

// Tests Decrypt(), FromJSON(), and ToJSON()
func testDecrypt(t *testing.T, encryptedFile, decryptedFile, decryptedFileRaw string) {
	// Decrypt encrypted config
	_, configBytes, metadata := decryptFile(t, encryptedFile)

	// Read JSON wrappers for already-decrypted configs
	expectedWrapperJSON, err := os.ReadFile(decryptedFile)
	assert.NoError(t, err)
	expectedWrapperJSONRaw, err := os.ReadFile(decryptedFileRaw)
	assert.NoError(t, err)

	// Get config bytes and metadata from JSON wrappers
	expectedConfigBytes, expectedMetadata, err := FromJSON(expectedWrapperJSON)
	assert.NoError(t, err)
	expectedConfigBytesRaw, expectedMetadataRaw, err := FromJSON(expectedWrapperJSONRaw)
	assert.NoError(t, err)

	// Verify that we have the expected config bytes
	assert.Equal(t, configBytes, expectedConfigBytes)
	assert.Equal(t, configBytes, expectedConfigBytesRaw)

	// Verify that we have the expected metadata
	assert.Equal(t, metadata, expectedMetadata)
	assert.Equal(t, metadata, expectedMetadataRaw)

	// Convert config bytes and metadata to JSON wrapper
	wrapperJSON, err := ToJSON(configBytes, metadata, false)
	assert.NoError(t, err)

	// Convert config bytes and metadata to JSON wrapper (raw)
	wrapperJSONRaw, err := ToJSON(configBytes, metadata, true)
	assert.NoError(t, err)

	// Compare with expected JSON wrappers
	assert.Equal(t, wrapperJSON, expectedWrapperJSON)
	assert.Equal(t, wrapperJSONRaw, expectedWrapperJSONRaw)
}

func TestEncryptDecrypt(t *testing.T) {
	for _, d := range devices {
		// Read JSON wrapper for already-decrypted config
		wrapperJSON, err := os.ReadFile(filepath.Join(testDataDir, d, decryptedConfigFile))
		assert.NoError(t, err)

		// Unmarshal into wrapper struct
		w := wrapper{}
		err = json.Unmarshal(wrapperJSON, &w)
		assert.NoError(t, err)

		// Add a new entry to config and marshal back into JSON wrapper
		w.Config.Set("my-new-key", "foobar")
		wrapperJSON, err = json.Marshal(w)
		assert.NoError(t, err)

		// Get raw config bytes from JSON wrapper and encrypt them
		configBytes, metadata, err := FromJSON(wrapperJSON)
		assert.NoError(t, err)

		encryptedConfig, err := Encrypt(configBytes, metadata)
		assert.NoError(t, err)

		// Decrypt the modified config back into JSON and load it into a map
		_, configBytes, metadata, err = Decrypt(encryptedConfig)
		assert.NoError(t, err)

		wrapperJSON, err = ToJSON(configBytes, metadata, false)
		assert.NoError(t, err)

		w1 := wrapper{}
		err = json.Unmarshal(wrapperJSON, &w1)
		assert.NoError(t, err)

		// Verify that the new entry is present
		val, _ := w1.Config.Get("my-new-key")
		assert.Equal(t, val, "foobar")
	}
}

func TestChecksum(t *testing.T) {
	for _, d := range devices {
		encryptedConfig, err := os.ReadFile(filepath.Join(testDataDir, d, encryptedConfigFile))
		assert.NoError(t, err)

		// Verify that decryption works with the existing checksum
		header, configBytes, metadata, err := Decrypt(encryptedConfig)
		assert.NoError(t, err)

		// Verify that we produce the same checksum
		assert.Equal(t, header.Crc, calcChecksum(configBytes))

		// Make the checksum invalid and try to decrypt
		oldChecksum := header.Crc
		header.Crc = 0xeeeeeeee
		copy(encryptedConfig[metadata.HeaderOffset:metadata.HeaderOffset+headerSize], header.Bytes())
		_, _, _, err = Decrypt(encryptedConfig)
		assert.EqualError(t, err, ErrInvalidChecksum.Error())

		// Restore the proper checksum
		header.Crc = oldChecksum
		copy(encryptedConfig[metadata.HeaderOffset:metadata.HeaderOffset+headerSize], header.Bytes())
		_, _, _, err = Decrypt(encryptedConfig)
		assert.NoError(t, err)
	}
}

func FuzzDecrypt(f *testing.F) {
	encryptedConfig, err := os.ReadFile(filepath.Join(testDataDir, devices[0], encryptedConfigFile))
	assert.NoError(f, err)
	encryptedConfigSoap, err := os.ReadFile(filepath.Join(testDataDir, devices[0], encryptedConfigFileSoap))
	assert.NoError(f, err)

	f.Add(encryptedConfig)
	f.Add(encryptedConfigSoap)
	f.Fuzz(func(t *testing.T, b []byte) {
		Decrypt(b)
	})
}

func FuzzEncrypt(f *testing.F) {
	wrapperJSON, err := os.ReadFile(filepath.Join(testDataDir, devices[0], decryptedConfigFile))
	assert.NoError(f, err)
	wrapperJSONSoap, err := os.ReadFile(filepath.Join(testDataDir, devices[0], decryptedConfigFileSoap))
	assert.NoError(f, err)

	configBytes, metadata, err := FromJSON(wrapperJSON)
	assert.NoError(f, err)
	configBytesSoap, metadataSoap, err := FromJSON(wrapperJSONSoap)
	assert.NoError(f, err)

	f.Add(configBytes, metadata.HeaderOffset, metadata.StatedMagic, metadata.RealMagic, metadata.Rng)
	f.Add(configBytesSoap, metadataSoap.HeaderOffset, metadataSoap.StatedMagic, metadataSoap.RealMagic, metadataSoap.Rng)
	f.Fuzz(func(t *testing.T, cb []byte, headerOffset uint64, statedMagic, realMagic uint32, rng string) {
		m := Metadata{HeaderOffset: headerOffset, StatedMagic: statedMagic, RealMagic: realMagic, Rng: rng}
		Encrypt(cb, &m)
	})
}

func FuzzToJSON(f *testing.F) {
	encryptedConfig, err := os.ReadFile(filepath.Join(testDataDir, devices[0], encryptedConfigFile))
	assert.NoError(f, err)
	_, configBytes, metadata, err := Decrypt(encryptedConfig)
	assert.NoError(f, err)

	f.Add(configBytes, metadata.HeaderOffset, metadata.StatedMagic, metadata.RealMagic, metadata.Rng)
	f.Fuzz(func(t *testing.T, cb []byte, headerOffset uint64, statedMagic, realMagic uint32, rng string) {
		m := Metadata{HeaderOffset: headerOffset, StatedMagic: statedMagic, RealMagic: realMagic, Rng: rng}
		ToJSON(cb, &m, false)
		ToJSON(cb, &m, true)
	})
}

func FuzzFromJSON(f *testing.F) {
	wrapperJSON, err := os.ReadFile(filepath.Join(testDataDir, devices[0], decryptedConfigFile))
	assert.NoError(f, err)
	wrapperJSONSoap, err := os.ReadFile(filepath.Join(testDataDir, devices[0], decryptedConfigFileSoap))
	assert.NoError(f, err)
	wrapperJSONRaw, err := os.ReadFile(filepath.Join(testDataDir, devices[0], decryptedConfigFileRaw))
	assert.NoError(f, err)

	f.Add(wrapperJSON)
	f.Add(wrapperJSONSoap)
	f.Add(wrapperJSONRaw)
	f.Fuzz(func(t *testing.T, b []byte) {
		FromJSON(b)
	})
}

func decryptFile(t *testing.T, encryptedFile string) (*Header, []byte, *Metadata) {
	encryptedConfig, err := os.ReadFile(encryptedFile)
	assert.NoError(t, err)
	header, configBytes, metadata, err := Decrypt(encryptedConfig)
	assert.NoError(t, err)
	return header, configBytes, metadata
}
