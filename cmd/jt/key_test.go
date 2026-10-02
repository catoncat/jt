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
