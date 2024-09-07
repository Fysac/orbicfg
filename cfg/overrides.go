package cfg

import "fmt"

// Overrides are necessary because the magic value stated in the header is sometimes incorrect.
// This structure maps stated magic values to the known metadata for the device, including the real magic
var overrides = map[uint32]*Metadata{
	// RBR760 (https://github.com/Fysac/orbicfg/issues/6)
	0x01346231: {
		HeaderOffset: 0,
		StatedMagic:  0x01346231,
		RealMagic:    0x01346232,
		Rng:          RngMusl,
	},
}

func Overrides() map[uint32]*Metadata {
	for k, v := range overrides {
		// Sanity check
		if k != v.StatedMagic {
			panic(fmt.Errorf("key %v is not equal to StatedMagic %v", k, v.StatedMagic))
		}
	}
	return overrides
}