package cfg

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fysac/orbicfg/rand/musl"
	"github.com/fysac/orbicfg/rand/uclibc"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

const (
	// Different devices use either uClibc's or musl libc's rand(3) implementation
	RngUclibc = "uclibc"
	RngMusl   = "musl"

	// When a config is exported from the web interface, it looks like a tar archive.
	tarMarker = "photos.tar"

	// The real config data is located at this offset.
	// See: package/dni/circle/src/Binary/usr/bin/backup_cfg
	// XXX: is this RBR50-specific?
	configOffsetAfterTar = 655360

	// A header of this size immediately precedes the encrypted data.
	headerSize = 12

	// Data is encrypted in blocks of this size.
	chunkSize = 4

	// The starting and ending value when calculating and verifying a checksum, respectively.
	initialCrc uint32 = 0xffffffff
)

var ErrInvalidChecksum = errors.New("invalid checksum")

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
	headerBytes := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(headerBytes[:4], header.Magic)
	binary.LittleEndian.PutUint32(headerBytes[4:8], header.Len)
	binary.LittleEndian.PutUint32(headerBytes[8:headerSize], header.Crc)
	return headerBytes
}

type Metadata struct {
	// Offset of the config header in the encrypted file
	HeaderOffset uint64 `json:"header_offset"`

	// The magic value given in the header of the encrypted config
	// Depending on the device, this may not be the actual value used for encryption
	StatedMagic uint32 `json:"stated_magic"`

	// The magic value used for encryption
	RealMagic uint32 `json:"real_magic"`

	// The rand(3) implementation to use. Can be 'uclibc' or 'musl'
	Rng string `json:"rng"`
}

type wrapper struct {
	Metadata  *Metadata                              `json:"metadata"`
	Config    *orderedmap.OrderedMap[string, string] `json:"config,omitempty"`
	ConfigRaw []byte                                 `json:"config_raw,omitempty"`
}

func Decrypt(encryptedConfig []byte) (header *Header, configBytes []byte, metadata *Metadata, err error) {
	var offset uint64 = 0
	if bytes.HasPrefix(encryptedConfig, []byte(tarMarker)) {
		if len(encryptedConfig) <= configOffsetAfterTar {
			err = fmt.Errorf("offset should be %v, but config is too small (%v)", configOffsetAfterTar, len(encryptedConfig))
			return
		}
		offset = configOffsetAfterTar
	}

	header, err = parseHeader(encryptedConfig[offset:])
	if err != nil {
		return
	}

	// The magic value in the header is sometimes incorrect; check if we have an override for it
	if override, ok := Overrides()[header.Magic]; ok {
		metadata = override
		// Decrypt using the values in the override
		configBytes, err = xorCipher(header, encryptedConfig[offset+headerSize:], metadata)
		if err != nil {
			return
		}
		err = verifyChecksum(header, configBytes)
		return
	}

	// No overrides; take the header at face value
	metadata = &Metadata{HeaderOffset: offset, StatedMagic: header.Magic, RealMagic: header.Magic}

	// Try to decrypt using each supported RNG
	for _, rng := range []string{RngMusl, RngUclibc} {
		metadata.Rng = rng
		configBytes, err = xorCipher(header, encryptedConfig[offset+headerSize:], metadata)
		if err != nil {
			return
		}

		if err = verifyChecksum(header, configBytes); err == nil {
			// No need to try other RNGs if the checksum is good
			break
		}
	}
	return
}

func Encrypt(configBytes []byte, metadata *Metadata) ([]byte, error) {
	if len(configBytes) == 0 {
		return nil, errors.New("config is empty")
	}
	if len(configBytes)%chunkSize != 0 {
		return nil, errors.New("config length is not divisible by chunk size")
	}

	header := Header{
		/* To ensure the re-encrypted file is compatible with the device,
		we place the stated magic in the header, not necessarily the
		magic actually used for encryption. */
		Magic: metadata.StatedMagic,
		Len:   uint32(len(configBytes)),
		Crc:   calcChecksum(configBytes),
	}

	encryptedConfig, err := xorCipher(&header, configBytes, metadata)
	if err != nil {
		return nil, err
	}
	encryptedConfig = append(header.Bytes(), encryptedConfig...)

	if metadata.HeaderOffset != 0 {
		encryptedConfig = prependJunk(encryptedConfig, metadata.HeaderOffset)
	}
	return encryptedConfig, nil
}

func xorCipher(header *Header, input []byte, metadata *Metadata) ([]byte, error) {
	var randFunc func() int32
	switch metadata.Rng {
	case RngUclibc:
		uclibc.Srand(metadata.RealMagic)
		randFunc = uclibc.Rand
	case RngMusl:
		musl.Srand(metadata.RealMagic)
		randFunc = musl.Rand
	}

	output := make([]byte, header.Len)
	for i := uint32(0); i < header.Len; i += chunkSize {
		// XOR every 4 bytes with the next call to rand().
		result := binary.LittleEndian.Uint32(input[i:i+chunkSize]) ^ uint32(randFunc())
		binary.LittleEndian.PutUint32(output[i:], result)
	}
	return output, nil
}

func ToJSON(configBytes []byte, metadata *Metadata, raw bool) (wrapperJSON []byte, err error) {
	w := wrapper{Metadata: metadata}

	if raw {
		w.ConfigRaw = configBytes
	} else {
		// Use orderedmap to preserve original ordering of entries.
		config := orderedmap.New[string, string]()

		entries := bytes.Split(configBytes, []byte{0})
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
				return nil, errors.New("missing or improper '=' separator in config entry")
			}
			key := string(mapping[0])
			value := string(mapping[1])

			if _, present := config.Get(key); present {
				return nil, errors.New("config has duplicate key")
			}
			config.Set(key, value)
		}
		w.Config = config
	}

	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err = json.Indent(&buf, b, "", "    "); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	return buf.Bytes(), nil
}

func FromJSON(wrapperJSON []byte) (configBytes []byte, metadata *Metadata, err error) {
	w := wrapper{}
	err = json.Unmarshal(wrapperJSON, &w)
	if err != nil {
		return
	}

	if w.Metadata == nil {
		err = errors.New("'metadata' is required")
		return
	}
	metadata = w.Metadata

	if w.Config == nil && w.ConfigRaw == nil {
		err = errors.New("'config' or 'config_raw' is required")
		return
	}

	if w.Config != nil && w.ConfigRaw != nil {
		err = errors.New("only one of 'config' and 'config_raw' may be set")
		return
	}

	if w.Config != nil {
		for pair := w.Config.Oldest(); pair != nil; pair = pair.Next() {
			configBytes = append(configBytes, []byte(fmt.Sprintf("%s=%s", pair.Key, pair.Value))...)
			configBytes = append(configBytes, 0)
		}

		// XXX: is this really how padding is done?
		paddingLen := chunkSize - (len(configBytes) % chunkSize)
		configBytes = append(configBytes, bytes.Repeat([]byte{0}, paddingLen)...)
	} else {
		configBytes = w.ConfigRaw
	}
	return
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

func verifyChecksum(header *Header, configBytes []byte) error {
	crc := header.Crc
	for i := 0; i < len(configBytes); i += chunkSize {
		crc += binary.LittleEndian.Uint32(configBytes[i : i+4])
	}
	if crc != initialCrc {
		return ErrInvalidChecksum
	}
	return nil
}

func calcChecksum(configBytes []byte) uint32 {
	crc := initialCrc
	for i := 0; i < len(configBytes); i += chunkSize {
		crc -= binary.LittleEndian.Uint32(configBytes[i : i+4])
	}
	return crc
}

func prependJunk(encryptedConfig []byte, headerOffset uint64) []byte {
	count := headerOffset - uint64(len([]byte(tarMarker)))
	junk := append([]byte(tarMarker), bytes.Repeat([]byte{0}, int(count))...)
	return append(junk, encryptedConfig...)
}
