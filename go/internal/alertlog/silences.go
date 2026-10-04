package alertlog

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Silence is one alerts.silences row, the TSV bash alert_silence_add writes:
//
//	<key_or_glob>  <until_epoch>  <added_epoch>  <added_by>  <message>
type Silence struct {
	Key     string
	Until   int64
	Added   int64
	AddedBy string
	Message string
}

// Matches mirrors bash `[[ $rule == $key ]]`; `/` is swapped out because path.Match's `*` stops at it and audit keys hold paths.
func (s Silence) Matches(rule string) bool {
	if rule == s.Key {
		return true
	}
	ok, _ := path.Match(strings.ReplaceAll(s.Key, "/", "\x00"), strings.ReplaceAll(rule, "/", "\x00"))
	return ok
}

// LoadSilences returns the rows still active at now, in file order. A
// missing file returns no rows; malformed rows are skipped.
func LoadSilences(file string, now time.Time) ([]Silence, error) {
	all, err := readSilences(file)
	var active []Silence
	for _, s := range all {
		if s.Until > now.Unix() {
			active = append(active, s)
		}
	}
	return active, err
}

// AddSilence writes the same row bash `milog silence <key> <dur>` would,
// replacing any row for key and dropping expired ones.
func AddSilence(file, key string, d time.Duration, message string, now time.Time) (Silence, error) {
	if key == "" || strings.ContainsAny(key, "\t\r\n") {
		return Silence{}, fmt.Errorf("invalid silence key: %q", key)
	}
	if d < time.Second {
		return Silence{}, fmt.Errorf("duration must be at least 1s")
	}
	rows, err := LoadSilences(file, now)
	if err != nil {
		return Silence{}, err
	}
	message = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(message)
	if r := []rune(message); len(r) > 200 {
		message = string(r[:200])
	}
	s := Silence{
		Key:     key,
		Until:   now.Unix() + int64(d/time.Second),
		Added:   now.Unix(),
		AddedBy: currentUser(),
		Message: message,
	}
	kept := rows[:0]
	for _, r := range rows {
		if r.Key != key {
			kept = append(kept, r)
		}
	}
	return s, writeSilences(file, append(kept, s))
}

// RemoveSilence drops every row whose key is exactly key; removed is false
// when none matched, and the file is left untouched.
func RemoveSilence(file, key string) (removed bool, err error) {
	rows, err := readSilences(file)
	if err != nil {
		return false, err
	}
	kept := rows[:0]
	for _, r := range rows {
		if r.Key == key {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	if !removed {
		return false, nil
	}
	return true, writeSilences(file, kept)
}

const maxSilenceSec = 3650 * 86400

// ParseDuration accepts what bash alert_silence_parse_duration does: bare
// seconds or N followed by s, m, h or d, up to 3650d.
func ParseDuration(s string) (time.Duration, error) {
	num, unitSec := s, uint64(1)
	units := map[string]uint64{"s": 1, "m": 60, "h": 3600, "d": 86400}
	if len(s) >= 2 {
		if u, ok := units[strings.ToLower(s[len(s)-1:])]; ok {
			num, unitSec = s[:len(s)-1], u
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use N<s|m|h|d>, e.g. 30m, 2h)", s)
	}
	if n > maxSilenceSec/unitSec {
		return 0, fmt.Errorf("duration %q is longer than 3650d", s)
	}
	return time.Duration(n*unitSec) * time.Second, nil
}

func readSilences(file string) ([]Silence, error) {
	f, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var rows []Silence
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 5)
		if len(p) < 2 || p[0] == "" {
			continue
		}
		until, err := strconv.ParseInt(p[1], 10, 64)
		if err != nil {
			continue
		}
		s := Silence{Key: p[0], Until: until}
		if len(p) > 2 {
			s.Added, _ = strconv.ParseInt(p[2], 10, 64)
		}
		if len(p) > 3 {
			s.AddedBy = p[3]
		}
		if len(p) > 4 {
			s.Message = p[4]
		}
		rows = append(rows, s)
	}
	return rows, sc.Err()
}

// writeSilences replaces file via rename so the bash daemon never reads a partial file.
func writeSilences(file string, rows []Silence) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), filepath.Base(file)+".add.")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, s := range rows {
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\n", s.Key, s.Until, s.Added, s.AddedBy, s.Message)
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}

// currentUser matches bash's ${USER:-$(id -un)}.
func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}
