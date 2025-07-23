package attestedkms

import (
	"bytes"
	"errors"
)

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.EncodeTo(inner)
		if err != nil {
			return err
		}
	}
	out.Write(s.tagBytes)
	err := encodeLength(out, inner.Len())
	if err != nil {
		return err
	}
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	out.Write(p.content)
	return nil
}

// Convert BER or DER in DER ASN.1 format
func EnsureDER(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("input ber is empty")
	}
	out := new(bytes.Buffer)

	obj, _, err := readBERObject(raw, 0)
	if err != nil {
		return nil, err
	}

	err = obj.EncodeTo(out)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//
//	length | byte 1 | bytes n
//	0      | 0x00   | -
//	120    | 0x78   | -
//	200    | 0x81   | 0xC8
//	500    | 0x82   | 0x01 0xF4
func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

//	Class P/C   Tag type
//
// | 0 0 | 0 | 1 0 0 0 0 |
func readBERObject(ber []byte, offset int) (asn1Object, int, error) {
	berLen := len(ber)
	if offset >= berLen {
		return nil, 0, errors.New("offset is after end of ber data")
	}
	tagStart := offset
	b := ber[offset]
	offset++
	if offset >= berLen {
		return nil, 0, errors.New("cannot move offset forward, end of ber data reached")
	}
	tag := b & 0b00011111
	if tag == 0b00011111 {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
			if offset > berLen {
				return nil, 0, errors.New("cannot move offset forward, end of ber data reached")
			}
		}

		offset++
		if offset > berLen {
			return nil, 0, errors.New("cannot move offset forward, end of ber data reached")
		}
	}
	tagEnd := offset

	// read length
	var length int
	l := ber[offset]
	offset++
	if offset > berLen {
		return nil, 0, errors.New("cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, errors.New("BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, errors.New("BER tag length is negative")
		}
		if (int)(ber[offset]) == 0x0 {
			return nil, 0, errors.New("BER tag length has leading zero")
		}

		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
			if offset > berLen {
				return nil, 0, errors.New("cannot move offset forward, end of ber data reached")
			}
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}
	if length < 0 {
		return nil, 0, errors.New("invalid negative value found in BER tag length")
	}

	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, errors.New("BER tag length is more than available data")
	}

	kind := b & 0b00100000
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, errors.New("Indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			var subObj asn1Object
			var err error
			subObj, offset, err = readBERObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)

			if indefinite {
				if len(ber)-offset < 2 {
					return nil, 0, errors.New("Invalid BER format")
				}

				if bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0 {
					break
				}
			}
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}
