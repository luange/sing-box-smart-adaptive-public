package cachefile

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/varbin"
)

// Dedicated codec for provider subscription cache (includes Hash).
// Kept separate from SavedBinary.MarshalBinary so rule-set cache format stays pure official.

func marshalSubscriptionBinary(s *adapter.SavedBinary) ([]byte, error) {
	if s == nil {
		return nil, io.ErrUnexpectedEOF
	}
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.BigEndian, uint8(1)); err != nil {
		return nil, err
	}
	hash, err := s.Hash.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err = varbin.WriteUvarint(&buffer, uint64(len(hash))); err != nil {
		return nil, err
	}
	if _, err = buffer.Write(hash); err != nil {
		return nil, err
	}
	if _, err = varbin.WriteUvarint(&buffer, uint64(len(s.Content))); err != nil {
		return nil, err
	}
	if _, err = buffer.Write(s.Content); err != nil {
		return nil, err
	}
	if err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix()); err != nil {
		return nil, err
	}
	if _, err = varbin.WriteUvarint(&buffer, uint64(len(s.LastEtag))); err != nil {
		return nil, err
	}
	if _, err = buffer.WriteString(s.LastEtag); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func unmarshalSubscriptionBinary(s *adapter.SavedBinary, data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return err
	}
	hashLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	hash := make([]byte, hashLength)
	if _, err = io.ReadFull(reader, hash); err != nil {
		return err
	}
	if err = s.Hash.UnmarshalBinary(hash); err != nil {
		return err
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	s.Content = make([]byte, contentLength)
	if _, err = io.ReadFull(reader, s.Content); err != nil {
		return err
	}
	var updated int64
	if err = binary.Read(reader, binary.BigEndian, &updated); err != nil {
		return err
	}
	s.LastUpdated = time.Unix(updated, 0)
	etagLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	etag := make([]byte, etagLength)
	if _, err = io.ReadFull(reader, etag); err != nil {
		return err
	}
	s.LastEtag = string(etag)
	return nil
}
