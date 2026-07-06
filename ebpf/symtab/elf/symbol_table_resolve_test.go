package elf

import (
	"debug/elf"
	"testing"

	"github.com/grafana/pyroscope/ebpf/symtab/gosym"
	"github.com/ianlancetaylor/demangle"
	"github.com/stretchr/testify/require"
)

// stubStrings is a minimal ElfSymbolReader that maps a string-table offset to a
// symbol name, so SymbolTable.Resolve can be exercised without a real ELF file.
type stubStrings map[int]string

func (s stubStrings) getString(start int, _ []demangle.Option) (string, bool) {
	n, ok := s[start]
	return n, ok
}

// TestSymbolTableResolveBounds reproduces coroot/coroot-node-agent#262: a
// stripped binary (e.g. an Envoy sidecar) keeps only a handful of exported
// .dynsym symbols. Before this fix, a PC inside a stripped-out function was
// attributed to the nearest surviving symbol below it. Now, when the symbol's
// size is known, such PCs resolve to "" (unknown) instead.
func TestSymbolTableResolveBounds(t *testing.T) {
	type sym struct {
		value uint64
		size  uint32
		name  string
	}
	input := []sym{
		{0x1000, 0x20, "exported_low"},  // like envoyGoFilterLogLevel
		{0x2000, 0x20, "exported_high"}, // like luaopen_jit
		{0x3000, 0, "asm_no_size"},      // st_size unknown -> legacy behavior
	}

	strings := stubStrings{}
	st := &SymbolTable{Index: FlatSymbolIndex{
		Links:  []elf.SectionHeader{{Offset: 0}, {Offset: 0}},
		Names:  make([]Name, len(input)),
		Values: gosym.NewPCIndex(len(input)),
		Sizes:  make([]uint32, len(input)),
	}}
	for i, s := range input {
		nameIdx := uint32(i + 1)
		st.Index.Names[i] = NewName(nameIdx, sectionTypeDynSym)
		st.Index.Values.Set(i, s.value)
		st.Index.Sizes[i] = s.size
		strings[int(nameIdx)] = s.name
	}
	st.SymReader = strings

	cases := []struct {
		pc   uint64
		want string
		desc string
	}{
		{0x0fff, "", "below the first symbol"},
		{0x1000, "exported_low", "start of exported_low"},
		{0x101f, "exported_low", "last byte of exported_low"},
		{0x1020, "", "one past exported_low end (previously misattributed)"},
		{0x1800, "", "gap between the two exported symbols"},
		{0x1fff, "", "stripped-out code just below exported_high"},
		{0x2000, "exported_high", "start of exported_high"},
		{0x2020, "", "past exported_high end"},
		{0x3000, "asm_no_size", "size-0 symbol resolves at its start"},
		{0x4000, "asm_no_size", "size-0 symbol keeps legacy nearest-symbol behavior"},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, st.Resolve(c.pc), "pc=0x%x (%s)", c.pc, c.desc)
	}
}
