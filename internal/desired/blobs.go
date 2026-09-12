package desired

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const blobTimeout = 15 * time.Second

func OpenBlobs(url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = blobTimeout
	opt.WriteTimeout = blobTimeout
	opt.DialTimeout = blobTimeout

	return redis.NewClient(opt), nil
}

func FetchBlobs(ctx context.Context, rdb *redis.Client, p *Pack) (map[string][]byte, error) {
	runtime := p.RuntimeProfiles()
	lists := unique(values(runtime))

	out, err := mgetHashes(ctx, rdb, p, lists)
	if err != nil {
		return nil, err
	}

	files := values(p.Data)

	// Политики профилей -- такие же блобы: без них поколение применится с
	// пустой политикой, то есть молча выключит правила приёма и инициаторы.
	for name := range runtime {
		if hash, ok := p.Policies[name]; ok {
			files = append(files, hash)
		}
	}

	for name, phash := range runtime {
		ids := parseUUIDList(string(out[phash]))
		if len(ids) == 0 {
			return nil, fmt.Errorf("pack: profile %q is empty", name)
		}

		for _, id := range ids {
			fhash, ok := p.Files[id]
			if !ok {
				return nil, fmt.Errorf("pack: profile %q references unknown file %s", name, id)
			}

			files = append(files, fhash)
		}
	}

	more, err := mgetHashes(ctx, rdb, p, unique(files))
	if err != nil {
		return nil, err
	}

	for hash, body := range more {
		out[hash] = body
	}

	return out, nil
}

func mgetHashes(ctx context.Context, rdb *redis.Client, p *Pack, hashes []string) (map[string][]byte, error) {
	if len(hashes) == 0 {
		return map[string][]byte{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, blobTimeout)
	defer cancel()

	keys := make([]string, len(hashes))
	for i, hash := range hashes {
		keys[i] = p.BlobKey(hash)
	}

	vals, err := rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}

	out := make(map[string][]byte, len(hashes))

	for i, raw := range vals {
		if raw == nil {
			return nil, fmt.Errorf("redis: missing %s", keys[i])
		}

		body, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("redis: %s: unexpected type %T", keys[i], raw)
		}

		buf := []byte(body)
		if hashOf(buf) != hashes[i] {
			return nil, fmt.Errorf("redis: %s hash mismatch", keys[i])
		}

		out[hashes[i]] = buf
	}

	return out, nil
}

func values(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func unique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))

	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}
		out = append(out, v)
	}

	return out
}
