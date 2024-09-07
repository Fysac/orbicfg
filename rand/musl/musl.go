// musl libc random number generator
// Derived from src/prng/rand.c

package musl

var state uint64

func Srand(seed uint32) {
	state = uint64(seed - 1)
}

func Rand() int32 {
	state = 6364136223846793005*state + 1
	return int32(state >> 33)
}
