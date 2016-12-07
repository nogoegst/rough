// util.go
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of rough, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package rough

import (
	"crypto/rand"
	"encoding/binary"
)

func RandUint16() uint16 {
	buf := make([]byte, 2)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint16(buf)
}

func RandUint32() uint32 {
	buf := make([]byte, 4)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(buf)
}
