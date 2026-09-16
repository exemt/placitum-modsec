package engine

import (
	"fmt"
	"strconv"
	"strings"
)

type Ranges [][2]int

func ParseRanges(items []string) (Ranges, error) {
	var out Ranges

	for _, item := range items {
		lo, hi, ok := cutRange(strings.TrimSpace(item))
		if !ok {
			return nil, fmt.Errorf("invalid rule id or range: %q", item)
		}

		out = append(out, [2]int{lo, hi})
	}

	return out, nil
}

func (rs Ranges) Has(id int) bool {
	for _, rng := range rs {
		if id >= rng[0] && id <= rng[1] {
			return true
		}
	}

	return false
}

func cutRange(item string) (int, int, bool) {
	if lo, hi, found := strings.Cut(item, "-"); found {
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)

		if err1 != nil || err2 != nil || l < 0 || l > h {
			return 0, 0, false
		}

		return l, h, true
	}

	v, err := strconv.Atoi(item)
	if err != nil || v < 0 {
		return 0, 0, false
	}

	return v, v, true
}
