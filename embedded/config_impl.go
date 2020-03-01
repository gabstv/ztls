package embedded

import (
	"encoding/pem"

	"github.com/golang/protobuf/proto"
)

type err0 string

func (e err0) Error() string {
	return string(e)
}

const (
	errInvalidPEM err0 = "invalid PEM encoding"
)

func UnmarshalConfig(pemcfg []byte) (*Config, error) {
	b, _ := pem.Decode(pemcfg)
	if b == nil {
		return nil, errInvalidPEM
	}
	if b.Type != "ZTLSCONFIG" {
		return nil, errInvalidPEM
	}
	cfg := &Config{}
	if err := proto.Unmarshal(b.Bytes, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Marshal(metad map[string]string) (pemdata []byte) {
	bb, err := proto.Marshal(c)
	if err != nil {
		panic(err)
	}
	blk := &pem.Block{
		Type:    "ZTLSCONFIG",
		Bytes:   bb,
		Headers: metad,
	}
	pemdata = pem.EncodeToMemory(blk)
	return
}
