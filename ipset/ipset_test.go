package ipset

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    Header
		wantErr bool
	}{
		{
			name: "hash:ip with timeout",
			out: `Name: test
Type: hash:ip
Revision: 4
Header: family inet hashsize 16384 maxelem 65536 timeout 3600
Size in memory: 2384984
References: 1
Number of entries: 65536
`,
			want: Header{Name: "test", HashType: "hash:ip", HashFamily: "inet", HashSize: 16384, MaxElem: 65536,
				Timeout: 3600, MemSize: 2384984, References: 1, Entries: 65536},
		},
		{
			name: "hash:net with flags and newer options",
			out: `Name: test-net
Type: hash:net
Revision: 7
Header: family inet6 hashsize 1024 maxelem 262144 counters comment bucketsize 12 initval 0x8d3c3e3a
Size in memory: 1048
References: 0
Number of entries: 2
`,
			want: Header{Name: "test-net", HashType: "hash:net", HashFamily: "inet6", HashSize: 1024, MaxElem: 262144,
				MemSize: 1048, Entries: 2},
		},
		{
			name:    "no entries line",
			out:     "Name: x\nHeader: family inet hashsize 1024 maxelem 65536\n",
			wantErr: true,
		},
		{
			name:    "no header line",
			out:     "Name: x\nNumber of entries: 1\n",
			wantErr: true,
		},
		{
			name:    "bad maxelem",
			out:     "Header: family inet maxelem abc\nNumber of entries: 1\n",
			wantErr: true,
		},
		{
			name:    "empty output",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeader([]byte(tt.out))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if *got != tt.want {
				t.Errorf("parseHeader() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestTempSetName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"test", "test-temp"},
		{strings.Repeat("a", 26), strings.Repeat("a", 26) + "-temp"},
		{strings.Repeat("a", 31), strings.Repeat("a", 26) + "-temp"},
	}

	for _, tt := range tests {
		if got := tempSetName(tt.name); got != tt.want || len(got) > maxNameLen {
			t.Errorf("tempSetName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// requireIpset skips integration tests, which need root and ipset utility.
func requireIpset(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root")
	}
	if _, err := exec.LookPath("ipset"); err != nil {
		t.Skip("integration test requires ipset utility")
	}
}

func newTestSet(t *testing.T, name string, p *Params) *IPSet {
	t.Helper()
	s, err := New(name, "hash:ip", p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = destroyIPSet(name) })
	return s
}

func TestHeaderIntegration(t *testing.T) {
	requireIpset(t)

	s := newTestSet(t, "go-ipset-test-header", &Params{MaxElem: 8, Timeout: 60})
	if err := s.Add("10.0.0.1", 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	h, err := s.Header()
	if err != nil {
		t.Fatalf("Header() error = %v", err)
	}
	if h.Name != s.Name || h.HashType != "hash:ip" || h.MaxElem != 8 || h.Timeout != 60 || h.Entries != 1 {
		t.Errorf("Header() = %+v", *h)
	}
}

func TestNewExistingChangedIntegration(t *testing.T) {
	requireIpset(t)

	name := "go-ipset-test-recreate"
	s := newTestSet(t, name, &Params{MaxElem: 4, Timeout: 60})
	if err := s.Add("10.0.0.1", 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Same params with existing set are fine
	if _, err := New(name, "hash:ip", &Params{MaxElem: 4, Timeout: 60}); err != nil {
		t.Fatalf("New() with same params error = %v", err)
	}

	// Kernel refuses to change existing set
	if _, err := New(name, "hash:ip", &Params{MaxElem: 8, Timeout: 60}); err == nil {
		t.Fatal("New() with changed maxelem without RecreateOnChange expected error")
	}

	// Leftover temporary set with other params must not break recreate
	if _, err := New(tempSetName(name), "hash:ip", &Params{MaxElem: 16}); err != nil {
		t.Fatalf("New() leftover error = %v", err)
	}

	for _, p := range []*Params{
		{MaxElem: 8, Timeout: 60, RecreateOnChange: true},
		{MaxElem: 8, Timeout: 120, RecreateOnChange: true},
	} {
		if _, err := New(name, "hash:ip", p); err != nil {
			t.Fatalf("New(%+v) error = %v", *p, err)
		}

		h, err := ListHeader(name)
		if err != nil {
			t.Fatalf("ListHeader() error = %v", err)
		}
		if h.MaxElem != p.MaxElem || h.Timeout != p.Timeout || h.Entries != 0 {
			t.Errorf("ListHeader() after recreate = %+v, want %+v", *h, *p)
		}
	}

	if _, err := ListHeader(tempSetName(name)); err == nil {
		t.Error("temporary set is not destroyed")
	}
}

func TestNewExistingUnchangedIntegration(t *testing.T) {
	requireIpset(t)

	name := "go-ipset-test-unchanged"
	s := newTestSet(t, name, &Params{MaxElem: 4})
	if err := s.Add("10.0.0.1", 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Set is not recreated, entries are kept
	if _, err := New(name, "hash:ip", &Params{MaxElem: 4, RecreateOnChange: true}); err != nil {
		t.Fatalf("New() error = %v", err)
	}
	h, err := ListHeader(name)
	if err != nil {
		t.Fatalf("ListHeader() error = %v", err)
	}
	if h.Entries != 1 {
		t.Errorf("entries = %d, want 1", h.Entries)
	}
}
