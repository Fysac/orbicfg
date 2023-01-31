package cfg

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fysac/orbicfg/uclibc/rand"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

const (
	// When a config is exported from the web interface, it looks like a tar archive.
	tarMarker = "photos.tar"
	// The real config data is located at this offset.
	// See: package/dni/circle/src/Binary/usr/bin/backup_cfg
	configOffsetAfterTar = 655360

	// A header of this size immediately precedes the encrypted data.
	headerSize = 12

	// Data is encrypted in blocks of this size.
	chunkSize = 4

	// The starting and ending value when calculating and verifying a checksum, respectively.
	initialCrc uint32 = 0xffffffff
)

const (
	ErrorInvalidChecksum = "invalid checksum"
)

type Header struct {
	// Seed given to uClibc srand() to generate XOR keystream.
	// e.g., 0x20131224 or 0x23091293
	Magic uint32

	// Length of encrypted data following the header.
	Len uint32

	// Not an actual CRC, just a checksum.
	// datalib just calls the field `crc`, so we keep the name for consistency.
	Crc uint32
}

func (header *Header) Bytes() []byte {
	rawHeader := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(rawHeader[:4], header.Magic)
	binary.LittleEndian.PutUint32(rawHeader[4:8], header.Len)
	binary.LittleEndian.PutUint32(rawHeader[8:headerSize], header.Crc)
	return rawHeader
}

func Decrypt(encryptedConfig []byte, ignoreChecksum bool) (*Header, []byte, error) {
	if bytes.HasPrefix(encryptedConfig, []byte(tarMarker)) {
		if len(encryptedConfig) <= configOffsetAfterTar {
			return nil, nil, fmt.Errorf("offset should be %v, but config is too small (%v)", configOffsetAfterTar, len(encryptedConfig))
		}
		encryptedConfig = encryptedConfig[configOffsetAfterTar:]
	}

	header, err := parseHeader(encryptedConfig)
	if err != nil {
		return nil, nil, err
	}

	rd := rand.Srand(header.Magic)
	rawConfig := make([]byte, header.Len)

	for i := uint32(0); i < header.Len; i += chunkSize {
		// XOR every 4 bytes with the next call to uClibc rand().
		result := binary.LittleEndian.Uint32(encryptedConfig[headerSize+i:headerSize+i+chunkSize]) ^ uint32(rand.Rand(rd))
		binary.LittleEndian.PutUint32(rawConfig[i:], result)
	}

	if !ignoreChecksum && !verifyChecksum(header, rawConfig) {
		return nil, nil, errors.New(ErrorInvalidChecksum)
	}
	return header, rawConfig, nil
}

func Encrypt(rawConfig []byte, magic uint32) ([]byte, error) {
	if len(rawConfig) == 0 {
		return nil, errors.New("config is empty")
	}
	if len(rawConfig)%chunkSize != 0 {
		return nil, errors.New("config length is not divisible by chunk size")
	}

	header := Header{
		Magic: magic,
		Len:   uint32(len(rawConfig)),
		Crc:   calcChecksum(rawConfig),
	}

	rd := rand.Srand(magic)
	ct := make([]byte, header.Len)

	for i := uint32(0); i < header.Len; i += chunkSize {
		result := binary.LittleEndian.Uint32(rawConfig[i:i+chunkSize]) ^ uint32(rand.Rand(rd))
		binary.LittleEndian.PutUint32(ct[i:], result)
	}
	encryptedConfig := append(header.Bytes(), ct...)
	return prependJunk(encryptedConfig), nil
}

func ToJSON(rawConfig []byte) ([]byte, error) {
	// Use orderedmap to preserve original ordering of entries.
	jsonConfig := orderedmap.New[string, string]()

	entries := bytes.Split(rawConfig, []byte{0})
	if len(entries) == 0 {
		return nil, errors.New("config entries are not separated by null bytes")
	}

	for _, entry := range entries {
		if len(entry) == 0 {
			// The last two bytes of the plaintext are always 0, so there's nothing to split there.
			continue
		}

		mapping := bytes.Split(entry, []byte{'='})
		if len(mapping) != 2 {
			return nil, fmt.Errorf("missing or improper '=' separator in config: %v", entry)
		}
		key := string(mapping[0])
		value := string(mapping[1])

		if _, present := jsonConfig.Get(key); present {
			return nil, fmt.Errorf("config has duplicate key: %v", key)
		}
		jsonConfig.Set(key, value)
	}

	b, err := jsonConfig.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err = json.Indent(&buf, b, "", "\t"); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	return buf.Bytes(), nil
}

func FromJSON(jsonConfig []byte) ([]byte, error) {
	jsonConfigMap := orderedmap.New[string, string]()
	err := jsonConfigMap.UnmarshalJSON(jsonConfig)
	if err != nil {
		return nil, err
	}
	var rawConfig []byte

	for pair := jsonConfigMap.Oldest(); pair != nil; pair = pair.Next() {
		rawConfig = append(rawConfig, []byte(fmt.Sprintf("%s=%s", pair.Key, pair.Value))...)
		rawConfig = append(rawConfig, 0)
	}

	// XXX: is this really how padding is done?
	paddingLen := chunkSize - (len(rawConfig) % chunkSize)
	return append(rawConfig, bytes.Repeat([]byte{0}, paddingLen)...), nil
}

func parseHeader(encryptedConfig []byte) (*Header, error) {
	if len(encryptedConfig) < headerSize {
		return nil, fmt.Errorf("config is smaller than header size (%v < %v)", len(encryptedConfig), headerSize)
	}

	header := &Header{
		Magic: binary.LittleEndian.Uint32(encryptedConfig[:4]),
		Len:   binary.LittleEndian.Uint32(encryptedConfig[4:8]),
		Crc:   binary.LittleEndian.Uint32(encryptedConfig[8:headerSize]),
	}

	if int(header.Len) != len(encryptedConfig[headerSize:]) {
		return nil, fmt.Errorf("header length (%v) != length of config data (%v)", header.Len, len(encryptedConfig[headerSize:]))
	}
	if header.Len%chunkSize != 0 {
		return nil, fmt.Errorf("header length %v is not divisible by chunk size", header.Len)
	}
	return header, nil
}

func verifyChecksum(header *Header, rawConfig []byte) bool {
	crc := header.Crc
	for i := 0; i < len(rawConfig); i += chunkSize {
		crc += binary.LittleEndian.Uint32(rawConfig[i : i+4])
	}
	return crc == initialCrc
}

func calcChecksum(rawConfig []byte) uint32 {
	crc := initialCrc
	for i := 0; i < len(rawConfig); i += chunkSize {
		crc -= binary.LittleEndian.Uint32(rawConfig[i : i+4])
	}
	return crc
}

func prependJunk(encryptedConfig []byte) []byte {
	junk := append([]byte(tarMarker),
		bytes.Repeat([]byte{0}, configOffsetAfterTar-len([]byte(tarMarker)))...)
	return append(junk, encryptedConfig...)
}
