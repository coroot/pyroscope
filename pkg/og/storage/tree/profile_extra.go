package tree

// These functions are kept separately as profile.pb.go is a generated file

import (
	"sort"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"
	"github.com/grafana/pyroscope/pkg/og/agent/spy"
	"github.com/valyala/bytebufferpool"
)

type cacheKey []int64

type cacheEntry struct {
	key cacheKey
	val *spy.Labels
}
type cache struct {
	data []*cacheEntry
}

func newCache() *cache {
	return &cache{
		data: []*cacheEntry{},
	}
}

func getCacheKey(l []*profilev1.Label) cacheKey {
	r := []int64{}
	for _, x := range l {
		if x.Str != 0 {
			r = append(r, x.Key, x.Str)
		}
	}
	return r
}

func eq(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (c *cache) pprofLabelsToSpyLabels(x *profilev1.Profile, pprofLabels []*profilev1.Label) *spy.Labels {
	k := getCacheKey(pprofLabels)
	for _, e := range c.data {
		if eq(e.key, k) {
			return e.val
		}
	}

	l := spy.NewLabels()
	for _, pl := range pprofLabels {
		if pl.Str != 0 {
			l.Set(x.StringTable[pl.Key], x.StringTable[pl.Str])
		}
	}
	newVal := &cacheEntry{
		key: k,
		val: l,
	}
	c.data = append(c.data, newVal)
	return l
}

func Get(x *profilev1.Profile, sampleType string, cb func(labels *spy.Labels, name []byte, val int) error) error {
	valueIndex := 0
	if sampleType != "" {
		for i, v := range x.SampleType {
			if x.StringTable[v.Type] == sampleType {
				valueIndex = i
				break
			}
		}
	}

	labelsCache := newCache()

	b := bytebufferpool.Get()
	defer bytebufferpool.Put(b)

	for _, s := range x.Sample {
		for i := len(s.LocationId) - 1; i >= 0; i-- {
			name, ok := FindFunctionName(x, s.LocationId[i])
			if !ok {
				continue
			}
			if b.Len() > 0 {
				_ = b.WriteByte(';')
			}
			_, _ = b.WriteString(name)
		}

		labels := labelsCache.pprofLabelsToSpyLabels(x, s.Label)
		if err := cb(labels, b.Bytes(), int(s.Value[valueIndex])); err != nil {
			return err
		}

		b.Reset()
	}

	return nil
}

func SampleTypes(x *profilev1.Profile) []string {
	r := []string{}
	for _, v := range x.SampleType {
		r = append(r, x.StringTable[v.Type])
	}
	return r
}

func FindFunctionName(x *profilev1.Profile, locID uint64) (string, bool) {
	if loc, ok := FindLocation(x, locID); ok {
		if len(loc.Line) <= 0 {
			return "", false
		}

		if fn, ok := FindFunction(x, loc.Line[0].FunctionId); ok {
			return x.StringTable[fn.Name], true
		}
	}
	return "", false
}

func FindLocation(x *profilev1.Profile, lid uint64) (*profilev1.Location, bool) {
	idx := sort.Search(len(x.Location), func(i int) bool {
		return x.Location[i].Id >= lid
	})
	if idx < len(x.Location) {
		if l := x.Location[idx]; l.Id == lid {
			return l, true
		}
	}
	return nil, false
}

func FindFunction(x *profilev1.Profile, fid uint64) (*profilev1.Function, bool) {
	idx := sort.Search(len(x.Function), func(i int) bool {
		return x.Function[i].Id >= fid
	})
	if idx < len(x.Function) {
		if f := x.Function[idx]; f.Id == fid {
			return f, true
		}
	}
	return nil, false
}
