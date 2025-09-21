package main

import (
    "sort"
    "strings"
    "unicode"
    "unicode/utf8"

    "github.com/mandiant/GoReSym/objfile"
)

// StringInfo holds a discovered string and where it came from.
type StringInfo struct {
    Value   string `json:"value"`
    Address uint64 `json:"address"`
    Section string `json:"section"`
}

// StringsResult is returned by extractStrings.
type StringsResult struct {
    Strings []StringInfo `json:"strings"`
    Count   int          `json:"count"`
}

// extractStrings extracts printable ASCII and UTF-8 strings from useful sections.
// minLength is the minimum run length for a string to be considered.
func extractStrings(file *objfile.File, minLength int) (*StringsResult, error) {
    var results []StringInfo

    // Helper to pull strings from a section by name and data function
    pull := func(sectionName string, dataFn func() (uint64, []byte, error)) {
        start, data, err := dataFn()
        if err != nil || len(data) == 0 {
            return
        }
        strs := extractPrintableStrings(data, minLength)
        for _, s := range strs {
            results = append(results, StringInfo{
                Value:   s.Value,
                Address: start + s.Address,
                Section: sectionName,
            })
        }
    }

    // Text section
    pull(".text", file.Text)

    // Some binaries also place strings in read-only or rel.ro areas. Best-effort.
    if start, data, err := file.RData(); err == nil && len(data) > 0 {
        strs := extractPrintableStrings(data, minLength)
        for _, s := range strs {
            results = append(results, StringInfo{Value: s.Value, Address: start + s.Address, Section: ".rodata"})
        }
    }
    if start, data, err := file.RelRData(); err == nil && len(data) > 0 {
        strs := extractPrintableStrings(data, minLength)
        for _, s := range strs {
            results = append(results, StringInfo{Value: s.Value, Address: start + s.Address, Section: ".data.rel.ro"})
        }
    }

    // Deduplicate and sort by address for stable output
    results = deduplicateStrings(results)
    sort.Slice(results, func(i, j int) bool { return results[i].Address < results[j].Address })

    return &StringsResult{Strings: results, Count: len(results)}, nil
}

// localStringInfo mirrors StringInfo but Address is offset within provided buffer.
type localStringInfo struct {
    Value   string
    Address uint64
}

func extractPrintableStrings(b []byte, minLength int) []localStringInfo {
    var acc []localStringInfo

    // ASCII scan
    ascii := extractASCIIStrings(b, minLength)
    acc = append(acc, ascii...)

    // UTF-8 scan (find multi-byte sequences that are printable)
    utf := extractUTF8Strings(b, minLength)
    acc = append(acc, utf...)

    return acc
}

func extractASCIIStrings(b []byte, minLength int) []localStringInfo {
    var res []localStringInfo
    start := -1
    for i, c := range b {
        if isPrintableASCII(c) {
            if start == -1 {
                start = i
            }
        } else {
            if start != -1 {
                if l := i - start; l >= minLength {
                    s := string(b[start:i])
                    if isLikelyString(s) {
                        res = append(res, localStringInfo{Value: s, Address: uint64(start)})
                    }
                }
                start = -1
            }
        }
    }
    if start != -1 {
        if l := len(b) - start; l >= minLength {
            s := string(b[start:])
            if isLikelyString(s) {
                res = append(res, localStringInfo{Value: s, Address: uint64(start)})
            }
        }
    }
    return res
}

func extractUTF8Strings(b []byte, minLength int) []localStringInfo {
    var res []localStringInfo
    i := 0
    for i < len(b) {
        r, size := utf8.DecodeRune(b[i:])
        if r == utf8.RuneError && size == 1 {
            i++
            continue
        }
        // Start of a potential UTF-8 run
        j := i
        printable := 0
        for j < len(b) {
            r2, s2 := utf8.DecodeRune(b[j:])
            if r2 == utf8.RuneError && s2 == 1 {
                break
            }
            if r2 == '\n' || r2 == '\r' || r2 == '\t' {
                // allow whitespace breaks as delimiters
                break
            }
            if unicode.IsControl(r2) {
                break
            }
            printable++
            j += s2
        }
        if printable >= minLength {
            s := string(b[i:j])
            if !isPureASCII(s) && isLikelyString(s) {
                res = append(res, localStringInfo{Value: s, Address: uint64(i)})
            }
        }
        if j == i {
            i += size
        } else {
            i = j + 1
        }
    }
    return res
}

func isPrintableASCII(b byte) bool {
    // Visible ASCII and space
    return (b >= 32 && b <= 126)
}

func isPureASCII(s string) bool {
    for i := 0; i < len(s); i++ {
        if s[i] >= 0x80 {
            return false
        }
    }
    return true
}

func isLikelyString(s string) bool {
    // Heuristics to filter out code-like sequences and repeated noise
    trimmed := strings.TrimSpace(s)
    if len(trimmed) == 0 {
        return false
    }
    if isRepeatedChar(trimmed) {
        return false
    }
    // Most of the characters should be letters, digits, punctuation, or spaces
    good := 0
    for _, r := range trimmed {
        if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || isCommonPunctuation(r) {
            good++
        }
    }
    if good*100/len([]rune(trimmed)) < 70 {
        return false
    }
    if looksLikeAssemblyCode(trimmed) {
        return false
    }
    return true
}

func isCommonPunctuation(r rune) bool {
    switch r {
    case '.', ',', ':', ';', '!', '?', '\'', '"', '(', ')', '[', ']', '{', '}', '-', '_', '/', '\\', '+', '=', '*', '&', '|', '<', '>', '@', '#', '$', '%', '^', '~', '`':
        return true
    }
    return false
}

func isRepeatedChar(s string) bool {
    if len(s) < 3 {
        return false
    }
    first := s[0]
    for i := 1; i < len(s); i++ {
        if s[i] != first {
            return false
        }
    }
    return true
}

func looksLikeAssemblyCode(s string) bool {
    lower := strings.ToLower(s)
    // Filter typical instruction mnemonics and hex dumps
    asmHints := []string{"mov", "jmp", "call", "ret", "lea", "add", "sub", "xor", "push", "pop", "cmp", "test"}
    for _, h := range asmHints {
        if strings.Contains(lower, h+" ") || strings.HasPrefix(lower, h) {
            return true
        }
    }
    // High ratio of hex-like characters
    hex := 0
    for _, r := range lower {
        if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || r == 'x' {
            hex++
        }
    }
    if len(lower) > 0 && hex*100/len(lower) > 80 {
        return true
    }
    return false
}

func deduplicateStrings(in []StringInfo) []StringInfo {
    seen := make(map[string]bool)
    out := make([]StringInfo, 0, len(in))
    for _, s := range in {
        key := s.Section + "|" + s.Value
        if !seen[key] {
            seen[key] = true
            out = append(out, s)
        }
    }
    return out
}
