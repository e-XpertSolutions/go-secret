package secret

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/pkg/errors"
)

type hmap struct {
	m map[string][]byte
}

func decodeHmap(b []byte) (*hmap, error) {
	hm := &hmap{m: make(map[string][]byte)}
	if b == nil || len(b) == 0 {
		return hm, nil
	}
	for i := 0; i <= len(b)-1; {
		if b[i] != '{' {
			return nil, errors.Errorf("expected '{' for new key/value pair; got '%c'", b[i])
		}

		idx := bytes.Index(b[i:], []byte{'}'})
		if idx == -1 {
			return nil, errors.New("missing closing '}' for key/value pair")
		}

		tuple := bytes.Split(b[i+1:i+idx], []byte{':'})
		if len(tuple) != 2 {
			return nil, errors.New("malformed key/value pair")
		}
		key := string(tuple[0])
		value, err := base64.StdEncoding.DecodeString(string(tuple[1]))
		if err != nil {
			return nil, errors.New("malformed base64 value in key/value pair")
		}

		if err := hm.store(key, value); err != nil {
			return nil, errors.Wrap(err, "cannot save key/value pair")
		}

		i += idx + 1
	}
	return hm, nil
}

func (hm *hmap) store(key string, value []byte) error {
	if key == "" {
		return errors.New("key is empty")
	}
	if isValidKey(key) {
		return errors.New("key contains invalid characters")
	}
	hm.m[key] = value
	return nil
}

func (hm *hmap) load(key string) []byte {
	value, ok := hm.m[key]
	if !ok {
		return nil
	}
	return value
}

func (hm *hmap) delete(key string) {
	hm.delete(key)
}

func (hm *hmap) keys() []string {
	var keys []string
	for k := range hm.m {
		keys = append(keys, k)
	}
	return keys
}

func (hm *hmap) encode() []byte {
	var buf bytes.Buffer
	for k, v := range hm.m {
		buf.WriteByte('{')
		buf.Write([]byte(k))
		buf.WriteByte(':')
		buf.WriteString(base64.StdEncoding.EncodeToString(v))
		buf.WriteByte('}')
	}
	fmt.Println("=> ", buf.String())
	return buf.Bytes()
}

var reValidKey = regexp.MustCompile("^[a-zA-Z0-9_-]+$")

func isValidKey(key string) bool {
	return !reValidKey.MatchString(key)
}
