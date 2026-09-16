package verdict

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

const DefaultResponseName = "blocked"

type StatusMap struct {
	byStatus map[int]string
	fallback string
}

func BuiltinStatusMap() *StatusMap {
	return &StatusMap{
		byStatus: map[int]string{403: "blocked", 406: "blocked", 400: "malformed"},
		fallback: DefaultResponseName,
	}
}

func (m *StatusMap) Name(status int) string {
	if name, ok := m.byStatus[status]; ok {
		return name
	}

	return m.fallback
}

func LoadStatusMap(path string) (*StatusMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}

	m := &StatusMap{byStatus: make(map[int]string), fallback: DefaultResponseName}

	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected \"key: value\"", path, i+1)
		}

		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		if value == "" {
			return nil, fmt.Errorf("%s:%d: empty response name", path, i+1)
		}

		if key == "default" {
			m.fallback = value
			continue
		}

		status, err := strconv.Atoi(key)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}

		m.byStatus[status] = value
	}

	return m, nil
}
