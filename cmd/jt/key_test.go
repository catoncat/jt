package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func removeSetupKey(t *testing.T, vaultDir string) string {
	t.Helper()
	keyPath := filepath.Join(filepath.Dir(vaultDir), "key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

func assertMissingKeyDidNotWrite(t *testing.T, keyPath, vaultDir string, before []byte) {
	t.Helper()
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key was recreated: stat error = %v", err)
	}
	after, err := os.ReadFile(filepath.Join(vaultDir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("existing vault changed after missing-key failure")
	}
}

func TestAddDoesNotCreateReplacementKeyForExistingVault(t *testing.T) {
	ciphertext, err := seal(bytes.Repeat([]byte{1}, 32), "synthetic-existing-secret")
	if err != nil {
		t.Fatal(err)
	}
	vaultDir, _ := setup(t, []entry{{ID: "Abcd1234", Name: "old/KEY", Ciphertext: ciphertext}})
	keyPath := removeSetupKey(t, vaultDir)
	before, err := os.ReadFile(filepath.Join(vaultDir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	input(t, "synthetic-new-secret\n")

	err = add([]string{"new/KEY"})
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("add with a missing key should fail without replacement, got %v", err)
	}
	assertMissingKeyDidNotWrite(t, keyPath, vaultDir, before)
}

func TestInitDoesNotCreateReplacementKeyForExistingVault(t *testing.T) {
	vaultDir, _ := setup(t, []entry{{ID: "Abcd1234", Name: "old/KEY", Ciphertext: "synthetic-ciphertext"}})
	keyPath := removeSetupKey(t, vaultDir)
	before, err := os.ReadFile(filepath.Join(vaultDir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}

	err = initVault(nil)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("init with a missing key and existing vault should fail, got %v", err)
	}
	assertMissingKeyDidNotWrite(t, keyPath, vaultDir, before)
}

func freshHome(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("JT_HOME", home)
	t.Setenv("JT_VAULT_DIR", "")
	t.Setenv("JT_KEY_FILE", "")
	_, vaultDir, keyPath := paths()
	return vaultDir, keyPath
}

func assertSyntheticEntry(t *testing.T, vaultDir, keyPath string) {
	t.Helper()
	c := config{Vault: vaultDir, Key: keyPath}
	v, key, err := openVault(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Secrets) != 1 {
		t.Fatalf("want one secret, got %d", len(v.Secrets))
	}
	value, err := open(key, v.Secrets[0].Ciphertext)
	if err != nil || value != "synthetic-new-secret" {
		t.Fatalf("could not decrypt newly added synthetic secret: value %q, error %v", value, err)
	}
}

func TestAddCreatesKeyForNewVault(t *testing.T) {
	vaultDir, keyPath := freshHome(t)
	input(t, "synthetic-new-secret\n")
	if err := add([]string{"app/KEY"}); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil || len(key) != 32 {
		t.Fatalf("new vault key: got %d bytes, error %v", len(key), err)
	}
	assertSyntheticEntry(t, vaultDir, keyPath)
}

func TestInitCreatesKeyForNewVaultAndAddReusesIt(t *testing.T) {
	vaultDir, keyPath := freshHome(t)
	if err := initVault(nil); err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil || len(keyBefore) != 32 {
		t.Fatalf("initialized vault key: got %d bytes, error %v", len(keyBefore), err)
	}

	input(t, "synthetic-new-secret\n")
	if err := add([]string{"app/KEY"}); err != nil {
		t.Fatal(err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(keyAfter, keyBefore) {
		t.Fatalf("add did not reuse the initialized key: error %v", err)
	}
	assertSyntheticEntry(t, vaultDir, keyPath)
}
