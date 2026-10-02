package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	version = "0.3.0"
	prefix  = "jt://secret/"
)

type config struct {
	Vault string `json:"vault"`
	Key   string `json:"key"`
}
type entry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Ciphertext  string `json:"ciphertext"`
	Preview     string `json:"preview"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}
type vault struct {
	Version int     `json:"version"`
	Secrets []entry `json:"secrets"`
}

// stdout is where list/status write their output; tests swap it.
var stdout io.Writer = os.Stdout

var tokenPattern = regexp.MustCompile("^jt://secret/[0-9A-Za-z]{8}$")
var envPattern = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*$")
var idPattern = regexp.MustCompile("^[0-9A-Za-z]{8}$")

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	var err error
	switch os.Args[1] {
	case "add":
		err = add(os.Args[2:])
	case "ls", "list":
		err = list(os.Args[2:])
	case "set":
		err = set(os.Args[2:])
	case "describe":
		err = describe(os.Args[2:])
	case "rm", "remove":
		err = remove(os.Args[2:])
	case "mv", "rename":
		err = rename(os.Args[2:])
	case "resolve":
		err = resolve(os.Args[2:])
	case "env":
		err = env(os.Args[2:])
	case "init":
		err = initVault(os.Args[2:])
	case "sync":
		err = syncVault(os.Args[2:])
	case "status":
		err = status(os.Args[2:])
	case "version":
		fmt.Println("jt " + version)
	case "help", "--help", "-h":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "jt:", err)
		if e, ok := err.(exitStatusError); ok {
			os.Exit(e.code)
		}
		os.Exit(1)
	}
}
func usage() {
	fmt.Print("jt - encrypted, syncable secret references\n\nUsage:\n  jt init [--repo URL] [--vault DIR] [--key FILE]\n  jt add <name> [--from-clipboard] [--id ID] [--description TEXT]\n  jt ls [--json] [query]\n  jt set <name-or-ref> [--from-clipboard] [--description TEXT]\n  jt describe <name-or-ref> <description>\n  jt rm <name-or-ref>\n  jt mv <name-or-ref> <new-name>\n  jt resolve <name-or-ref> [--env NAME] --exec COMMAND [ARGS...]\n  jt env <namespace> -- COMMAND [ARGS...]\n  jt sync\n  jt status [--json]\n\nValues for add/set are read from stdin unless --from-clipboard is used.\nresolve without --exec prints the value and is intended for controlled use only.\ndescribe edits only metadata; pass an empty string to clear the description.\nDescriptions are plaintext, synced metadata; never put secrets in them.\nThe first nonempty description upgrades the vault to v2; upgrade all clients first.\nls --json prints id, ref, name, description, preview and timestamps; never ciphertext.\nstatus reports local vault state (uncommitted changes, commits not pushed) without network access.\n")
}
func paths() (string, string, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	base := os.Getenv("JT_HOME")
	if base == "" {
		base = filepath.Join(home, ".config", "jt")
	}
	vaultDir := os.Getenv("JT_VAULT_DIR")
	if vaultDir == "" {
		vaultDir = filepath.Join(base, "vault")
	}
	keyPath := os.Getenv("JT_KEY_FILE")
	if keyPath == "" {
		keyPath = filepath.Join(base, "key")
	}
	return filepath.Join(base, "config.json"), vaultDir, keyPath
}
func loadConfig() (config, error) {
	configPath, vaultDir, keyPath := paths()
	c := config{Vault: vaultDir, Key: keyPath}
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	return c, nil
}
func saveConfig(c config) error {
	configPath, _, _ := paths()
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(configPath, data, 0600)
}
func loadKey(path string, create bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		data = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			return nil, err
		}
		if err := atomicWrite(path, data, 0600); err != nil {
			return nil, err
		}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, errors.New("key file must contain 32 bytes")
	}
	return data, nil
}
// loadKeyForVault only generates a missing key when there is no local vault file yet.
// A fresh key cannot decrypt existing ciphertext, so replacing a missing key in place
// would silently make every existing secret unusable.
func loadKeyForVault(keyPath, vaultPath string, create bool) ([]byte, error) {
	if !create {
		return loadKey(keyPath, false)
	}
	if _, err := os.Stat(vaultPath); err == nil {
		return loadKey(keyPath, false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return loadKey(keyPath, true)
}

func openVault(c config, create bool) (vault, []byte, error) {
	path := filepath.Join(c.Vault, "vault.json")
	key, err := loadKeyForVault(c.Key, path, create)
	if err != nil {
		return vault{}, nil, fmt.Errorf("load key: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		return vault{Version: 1, Secrets: []entry{}}, key, nil
	}
	if err != nil {
		return vault{}, nil, fmt.Errorf("read vault: %w", err)
	}
	var v vault
	if err := json.Unmarshal(data, &v); err != nil {
		return v, nil, fmt.Errorf("read vault: %w", err)
	}
	if v.Version != 1 && v.Version != 2 {
		return v, nil, fmt.Errorf("unsupported vault version %d", v.Version)
	}
	return v, key, nil
}
func saveVault(c config, v vault) error {
	if v.Version != 1 && v.Version != 2 {
		return fmt.Errorf("unsupported vault version %d", v.Version)
	}
	// Older clients reject v2 instead of silently dropping unknown entry fields.
	// Never downgrade after descriptions have been cleared or entries removed.
	for _, item := range v.Secrets {
		if item.Description != "" {
			v.Version = 2
			break
		}
	}
	if err := os.MkdirAll(c.Vault, 0700); err != nil {
		return err
	}
	// Sort a copy: callers may still hold a pointer to an entry for their result.
	secrets := make([]entry, len(v.Secrets))
	copy(secrets, v.Secrets)
	v.Secrets = secrets
	sort.Slice(v.Secrets, func(i, j int) bool { return v.Secrets[i].Name < v.Secrets[j].Name })
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(c.Vault, "vault.json"), data, 0600)
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".jt-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
func cipherFor(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
func seal(key []byte, value string) (string, error) {
	aead, err := cipherFor(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	combined := append(nonce, aead.Seal(nil, nonce, []byte(value), nil)...)
	return base64.StdEncoding.EncodeToString(combined), nil
}
func open(key []byte, encoded string) (string, error) {
	aead, err := cipherFor(key)
	if err != nil {
		return "", err
	}
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(combined) < aead.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	nonce, ciphertext := combined[:aead.NonceSize()], combined[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("ciphertext authentication failed")
	}
	return string(plain), nil
}
func preview(value string) string {
	r := []rune(value)
	if len(r) <= 8 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-6) + string(r[len(r)-4:])
}
func newID(existing map[string]bool) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	buf := make([]byte, 8)
	for {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return "", err
		}
		id := make([]byte, 8)
		for i, b := range buf {
			id[i] = alphabet[int(b)%len(alphabet)]
		}
		if !existing[string(id)] {
			return string(id), nil
		}
	}
}
func readValue(fromClipboard bool) (string, error) {
	if fromClipboard {
		for _, candidate := range []string{"pbpaste", "wl-paste", "xclip"} {
			if _, err := exec.LookPath(candidate); err == nil {
				var cmd *exec.Cmd
				switch candidate {
				case "pbpaste", "wl-paste":
					cmd = exec.Command(candidate)
				default:
					cmd = exec.Command(candidate, "-selection", "clipboard", "-o")
				}
				out, err := cmd.Output()
				if err != nil {
					return "", err
				}
				return strings.TrimSuffix(string(out), "\n"), nil
			}
		}
		return "", errors.New("clipboard tool not found (pbpaste, wl-paste, or xclip)")
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}

type writeOptions struct {
	fromClipboard bool
	id            string
	description   *string // nil means leave the existing description unchanged.
	positional    []string
}

// Flags may precede or follow positional arguments. Use -- to end flags, or
// --description=TEXT for a description beginning with a dash.
func parseWriteFlags(args []string, allowID bool) (writeOptions, error) {
	var opts writeOptions
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			opts.positional = append(opts.positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			opts.positional = append(opts.positional, arg)
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if name != "--from-clipboard" && name != "--description" && !(allowID && name == "--id") {
			return opts, fmt.Errorf("unknown option %q", name)
		}
		if seen[name] {
			return opts, fmt.Errorf("duplicate option %s", name)
		}
		seen[name] = true
		if name == "--from-clipboard" {
			if hasValue {
				return opts, errors.New("--from-clipboard does not take a value")
			}
			opts.fromClipboard = true
			continue
		}
		if !hasValue {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return opts, fmt.Errorf("%s needs a value (use %s=TEXT for a value beginning with a dash)", name, name)
			}
			i++
			value = args[i]
		}
		switch name {
		case "--id":
			if !idPattern.MatchString(value) {
				return opts, errors.New("id must be 8 base62 characters")
			}
			opts.id = value
		case "--description":
			if !utf8.ValidString(value) {
				return opts, errors.New("description must be valid UTF-8")
			}
			opts.description = &value
		}
	}
	return opts, nil
}
func add(args []string) error {
	opts, err := parseWriteFlags(args, true)
	if err != nil {
		return err
	}
	positional := opts.positional
	if len(positional) != 1 || positional[0] == "" {
		return errors.New("add needs <name>")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, key, err := openVault(c, true)
	if err != nil {
		return err
	}
	value, err := readValue(opts.fromClipboard)
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("refusing to add an empty value")
	}
	for _, item := range v.Secrets {
		if item.Name == positional[0] {
			return fmt.Errorf("name already exists: %s", positional[0])
		}
	}
	id := opts.id
	if id == "" {
		ids := map[string]bool{}
		for _, item := range v.Secrets {
			ids[item.ID] = true
		}
		id, err = newID(ids)
		if err != nil {
			return err
		}
	}
	if !idPattern.MatchString(id) {
		return errors.New("id must be 8 base62 characters")
	}
	for _, item := range v.Secrets {
		if item.ID == id {
			return fmt.Errorf("id already exists: %s", id)
		}
	}
	ciphertext, err := seal(key, value)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	item := entry{ID: id, Name: positional[0], Ciphertext: ciphertext, Preview: preview(value), CreatedAt: now, UpdatedAt: now}
	if opts.description != nil {
		item.Description = *opts.description
	}
	v.Secrets = append(v.Secrets, item)
	if err := saveVault(c, v); err != nil {
		return err
	}
	fmt.Printf("added %s %s\n", positional[0], prefix+id)
	return nil
}

type listItem struct {
	ID          string  `json:"id"`
	Ref         string  `json:"ref"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Preview     string  `json:"preview"`
	CreatedAt   *string `json:"created_at"`
	UpdatedAt   *string `json:"updated_at"`
}

func list(args []string) error {
	asJSON := false
	queries := []string{}
	for _, arg := range args {
		if arg == "--json" {
			asJSON = true
		} else {
			queries = append(queries, arg)
		}
	}
	if len(queries) > 1 {
		return errors.New("ls accepts at most one query")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, _, err := openVault(c, false)
	if err != nil {
		return err
	}
	query := ""
	if len(queries) == 1 {
		query = queries[0]
	}
	items := filterEntries(v.Secrets, query)
	if asJSON {
		out := make([]listItem, 0, len(items))
		for _, item := range items {
			out = append(out, listItem{ID: item.ID, Ref: prefix + item.ID, Name: item.Name, Description: item.Description, Preview: item.Preview, CreatedAt: optional(item.CreatedAt), UpdatedAt: optional(item.UpdatedAt)})
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\n", data)
		return err
	}
	for _, item := range items {
		if item.Description == "" {
			fmt.Fprintf(stdout, "%s | %s | %s\n", item.Name, prefix+item.ID, item.Preview)
		} else {
			// Quote metadata so newlines and terminal controls cannot forge list rows.
			fmt.Fprintf(stdout, "%s | %s | %s | %s\n", item.Name, prefix+item.ID, item.Preview, strconv.QuoteToGraphic(item.Description))
		}
	}
	return nil
}
func filterEntries(secrets []entry, query string) []entry {
	lower := strings.ToLower(query)
	items := []entry{}
	for _, item := range secrets {
		if query != "" && !strings.Contains(strings.ToLower(item.Name), lower) && !strings.Contains(strings.ToLower(item.Description), lower) && !strings.Contains(item.ID, query) {
			continue
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
	return items
}
func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func find(v vault, ref string) (int, *entry, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, prefix) && !tokenPattern.MatchString(ref) {
		return -1, nil, errors.New("invalid secret reference")
	}
	for i := range v.Secrets {
		if prefix+v.Secrets[i].ID == ref || v.Secrets[i].Name == ref {
			return i, &v.Secrets[i], nil
		}
	}
	return -1, nil, errors.New("secret not found")
}
func set(args []string) error {
	opts, err := parseWriteFlags(args, false)
	if err != nil {
		return err
	}
	positional := opts.positional
	if len(positional) != 1 || positional[0] == "" {
		return errors.New("set needs <name-or-ref>")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, key, err := openVault(c, false)
	if err != nil {
		return err
	}
	index, item, err := find(v, positional[0])
	if err != nil {
		return err
	}
	value, err := readValue(opts.fromClipboard)
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("refusing to set an empty value")
	}
	ciphertext, err := seal(key, value)
	if err != nil {
		return err
	}
	if opts.description != nil {
		item.Description = *opts.description
	}
	item.Ciphertext = ciphertext
	item.Preview = preview(value)
	item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	v.Secrets[index] = *item
	if err := saveVault(c, v); err != nil {
		return err
	}
	fmt.Printf("updated %s %s\n", item.Name, prefix+item.ID)
	return nil
}

// describe never reads stdin or decrypts/re-encrypts the value. The ID,
// ciphertext, preview and creation time remain unchanged.
func describe(args []string) error {
	if len(args) != 2 || args[0] == "" {
		return errors.New("describe needs <name-or-ref> <description>; use an empty string to clear")
	}
	if !utf8.ValidString(args[1]) {
		return errors.New("description must be valid UTF-8")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, _, err := openVault(c, false)
	if err != nil {
		return err
	}
	_, item, err := find(v, args[0])
	if err != nil {
		return err
	}
	if item.Description != args[1] {
		item.Description = args[1]
		item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := saveVault(c, v); err != nil {
			return err
		}
	}
	fmt.Printf("described %s %s\n", item.Name, prefix+item.ID)
	return nil
}

func remove(args []string) error {
	if len(args) != 1 {
		return errors.New("rm needs <name-or-ref>")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, _, err := openVault(c, false)
	if err != nil {
		return err
	}
	index, item, err := find(v, args[0])
	if err != nil {
		return err
	}
	removed := *item
	v.Secrets = append(v.Secrets[:index], v.Secrets[index+1:]...)
	if err := saveVault(c, v); err != nil {
		return err
	}
	fmt.Printf("removed %s %s\n", removed.Name, prefix+removed.ID)
	return nil
}
func rename(args []string) error {
	if len(args) != 2 || args[1] == "" {
		return errors.New("mv needs <name-or-ref> <new-name>")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, _, err := openVault(c, false)
	if err != nil {
		return err
	}
	_, item, err := find(v, args[0])
	if err != nil {
		return err
	}
	for _, other := range v.Secrets {
		if other.Name == args[1] {
			return fmt.Errorf("name already exists: %s", args[1])
		}
	}
	item.Name = args[1]
	item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := saveVault(c, v); err != nil {
		return err
	}
	fmt.Printf("renamed %s %s\n", item.Name, prefix+item.ID)
	return nil
}
func resolve(args []string) error {
	if len(args) < 1 {
		return errors.New("resolve needs <name-or-ref>")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, key, err := openVault(c, false)
	if err != nil {
		return err
	}
	_, item, err := find(v, args[0])
	if err != nil {
		return err
	}
	value, err := open(key, item.Ciphertext)
	if err != nil {
		return err
	}
	rest := args[1:]
	envName := "JT_SECRET"
	command := []string{}
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--env":
			if i+1 >= len(rest) {
				return errors.New("--env needs a name")
			}
			envName = rest[i+1]
			i++
		case "--exec":
			command = rest[i+1:]
			if len(command) == 0 || command[0] == "" {
				return errors.New("--exec needs a command")
			}
			i = len(rest)
		default:
			return fmt.Errorf("unexpected argument %q", rest[i])
		}
	}
	if len(command) == 0 {
		fmt.Println(value)
		return nil
	}
	if !envPattern.MatchString(envName) {
		return errors.New("invalid environment variable name")
	}
	var cmd *exec.Cmd
	if len(command) == 1 {
		cmd = exec.Command("/bin/sh", "-c", command[0])
	} else {
		cmd = exec.Command(command[0], command[1:]...)
	}
	cmd.Env = append(os.Environ(), envName+"="+value)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return exitStatusError{status.ExitStatus()}
			}
		}
		return err
	}
	return nil
}

type exitStatusError struct{ code int }

func (e exitStatusError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }
func env(args []string) error {
	if len(args) < 3 || args[1] != "--" {
		return errors.New("env needs <namespace> -- COMMAND [ARGS...]")
	}
	namespace := args[0]
	c, err := loadConfig()
	if err != nil {
		return err
	}
	v, key, err := openVault(c, false)
	if err != nil {
		return err
	}
	environment := append([]string{}, os.Environ()...)
	injected := 0
	for _, item := range v.Secrets {
		if !strings.HasPrefix(item.Name, namespace+"/") {
			continue
		}
		name := strings.TrimPrefix(item.Name, namespace+"/")
		if !envPattern.MatchString(name) {
			return fmt.Errorf("invalid environment variable name in vault: %s", name)
		}
		value, err := open(key, item.Ciphertext)
		if err != nil {
			return err
		}
		environment = append(environment, name+"="+value)
		injected++
	}
	if injected == 0 {
		return fmt.Errorf("no secrets found for namespace %q", namespace)
	}
	command := args[2:]
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = environment
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return exitStatusError{status.ExitStatus()}
			}
		}
		return err
	}
	return nil
}

func initVault(args []string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	repo := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--repo":
			if i+1 >= len(args) {
				return errors.New("--repo needs URL")
			}
			repo = args[i+1]
			i++
		case "--vault":
			if i+1 >= len(args) {
				return errors.New("--vault needs DIR")
			}
			c.Vault = args[i+1]
			i++
		case "--key":
			if i+1 >= len(args) {
				return errors.New("--key needs FILE")
			}
			c.Key = args[i+1]
			i++
		default:
			return fmt.Errorf("unexpected argument %q", args[i])
		}
	}
	if err := saveConfig(c); err != nil {
		return err
	}
	if _, err := loadKey(c.Key, true); err != nil {
		return err
	}
	if err := os.MkdirAll(c.Vault, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(c.Vault, "vault.json")); errors.Is(err, os.ErrNotExist) {
		if err := saveVault(c, vault{Version: 1, Secrets: []entry{}}); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(c.Vault, ".git")); errors.Is(err, os.ErrNotExist) {
		if err := runGit(c.Vault, "init"); err != nil {
			return err
		}
		if repo != "" {
			if err := runGit(c.Vault, "remote", "add", "origin", repo); err != nil {
				return err
			}
		}
	} else if repo != "" {
		_ = runGit(c.Vault, "remote", "set-url", "origin", repo)
	}
	fmt.Printf("initialized vault %s\n", c.Vault)
	return nil
}
func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func remoteHasHeads(dir string) bool {
	cmd := exec.Command("git", "-C", dir, "ls-remote", "--exit-code", "--heads", "origin")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func syncVault(args []string) error {
	if len(args) > 0 {
		return errors.New("sync takes no arguments")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(c.Vault, ".git")); err != nil {
		return errors.New("vault is not a git repository; run jt init --repo URL")
	}
	if remoteHasHeads(c.Vault) {
		if err := runGit(c.Vault, "pull", "--rebase", "--autostash", "origin"); err != nil {
			return err
		}
	}
	if err := runGit(c.Vault, "add", "vault.json"); err != nil {
		return err
	}
	status := exec.Command("git", "-C", c.Vault, "diff", "--cached", "--quiet")
	if err := status.Run(); err != nil {
		if err := runGit(c.Vault, "commit", "-m", "Update encrypted secrets"); err != nil {
			return err
		}
	}
	return runGit(c.Vault, "push", "origin", "HEAD")
}

type vaultStatus struct {
	Vault string `json:"vault"`
	Key   string `json:"key"`
	Git   bool   `json:"git"`
	Dirty bool   `json:"dirty"`
	Ahead *int   `json:"ahead"`
}

// status only reads local git state; it never fetches, so "ahead" is relative to the last known remote ref.
func status(args []string) error {
	asJSON := false
	for _, arg := range args {
		if arg != "--json" {
			return fmt.Errorf("unexpected argument %q", arg)
		}
		asJSON = true
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	st := vaultStatus{Vault: c.Vault, Key: c.Key}
	if _, err := os.Stat(filepath.Join(c.Vault, ".git")); err == nil {
		st.Git = true
		out, err := gitOutput(c.Vault, "status", "--porcelain", "--", "vault.json")
		if err != nil {
			return err
		}
		st.Dirty = out != ""
		st.Ahead = commitsAhead(c.Vault)
	}
	if asJSON {
		data, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\n", data)
		return err
	}
	fmt.Fprintf(stdout, "vault  %s\nkey    %s\n", st.Vault, st.Key)
	switch {
	case !st.Git:
		fmt.Fprintln(stdout, "sync   not a git repository")
	case st.Dirty:
		fmt.Fprintln(stdout, "sync   uncommitted changes; run jt sync")
	case st.Ahead != nil && *st.Ahead > 0:
		fmt.Fprintf(stdout, "sync   %d commit(s) not pushed; run jt sync\n", *st.Ahead)
	default:
		fmt.Fprintln(stdout, "sync   up to date with the last known remote state")
	}
	return nil
}
func gitOutput(dir string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

// commitsAhead counts local commits missing from the upstream (or origin/<branch>); nil when there is no remote ref to compare with.
func commitsAhead(dir string) *int {
	base := "@{upstream}"
	if _, err := gitOutput(dir, "rev-parse", "--verify", "--quiet", base); err != nil {
		branch, err := gitOutput(dir, "symbolic-ref", "--short", "HEAD")
		if err != nil {
			return nil
		}
		base = "refs/remotes/origin/" + branch
		if _, err := gitOutput(dir, "rev-parse", "--verify", "--quiet", base); err != nil {
			return nil
		}
	}
	out, err := gitOutput(dir, "rev-list", "--count", base+"..HEAD")
	if err != nil {
		return nil
	}
	var n int
	if _, err := fmt.Sscanf(out, "%d", &n); err != nil {
		return nil
	}
	return &n
}
