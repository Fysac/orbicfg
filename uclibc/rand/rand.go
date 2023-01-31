// Implements the TYPE_3 random number generator used by uClibc
// Derived from random.c and random_r.c

package rand

const deg3 uint = 31
const sep3 uint = 3

var randtbl = [deg3]int32{
	-1726662223,
	379960547,
	1735697613,
	1040273694,
	1313901226,
	1627687941,
	-179304937,
	-2073333483,
	1780058412,
	-1989503057,
	-615974602,
	344556628,
	939512070,
	-1249116260,
	1507946756,
	-812545463,
	154635395,
	1388815473,
	-1926676823,
	525320961,
	-1009028674,
	968117788,
	-123449607,
	1284210865,
	435012392,
	-2017506339,
	-911064859,
	-370259173,
	1132637927,
	1398500161,
	-205601318,
}

type RandomData struct {
	frontIdx uint
	rearIdx  uint
	state    [deg3]int32
}

func Srand(seed uint32) *RandomData {
	state := randtbl
	kc := int32(deg3)

	word := int64(seed)
	if word == 0 {
		word = 1
	}

	state[0] = int32(word)

	var i int32
	for i = 1; i < kc; i++ {
		hi := word / 127773
		lo := word % 127773
		word = 16807*lo - 2836*hi
		if word < 0 {
			word += 2147483647
		}
		state[uint(i)] = int32(word)
	}

	rd := RandomData{
		frontIdx: sep3,
		rearIdx:  0,
		state:    state,
	}

	kc = kc*10 - 1
	for kc >= 0 {
		Rand(&rd)
		kc -= 1
	}
	return &rd
}

func Rand(rd *RandomData) int32 {
	val := rd.state[rd.frontIdx] + rd.state[rd.rearIdx]
	rd.state[rd.frontIdx] = val
	result := (val >> 1) & 0x7fffffff

	rd.frontIdx += 1
	if rd.frontIdx >= deg3 {
		rd.frontIdx = 0
		rd.rearIdx += 1
	} else {
		rd.rearIdx += 1
		if rd.rearIdx >= deg3 {
			rd.rearIdx = 0
		}
	}
	return result
}
