package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureResolveOutput(t *testing.T, args []string) (string, error) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = file
	defer func() {
		os.Stdout = original
		file.Close()
	}()
	resolveErr := resolve(args)
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(output), resolveErr
}

func TestResolveExecRequiresCommandWithoutExposingSecret(t *testing.T) {
	const value = "synthetic-resolve-test-secret"
	ciphertext, err := seal(bytes.Repeat([]byte{1}, 32), value)
	if err != nil {
		t.Fatal(err)
	}
	setup(t, []entry{{ID: "Abcd1234", Name: "app/KEY", Ciphertext: ciphertext}})
	for _, args := range [][]string{
		{"app/KEY", "--exec"},
		{"app/KEY", "--env", "TOKEN", "--exec"},
		{"app/KEY", "--exec", ""},
		{"app/KEY", "--exec", "", "ignored"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output, err := captureResolveOutput(t, args)
			if err == nil || err.Error() != "--exec needs a command" {
				t.Fatalf("expected missing command error, got %v", err)
			}
			if output != "" {
				t.Fatalf("invalid --exec emitted output: %q", output)
			}
		})
	}
}

func TestResolveExplicitPlaintextAndExecModes(t *testing.T) {
	const value = "synthetic-resolve-test-secret"
	ciphertext, err := seal(bytes.Repeat([]byte{1}, 32), value)
	if err != nil {
		t.Fatal(err)
	}
	setup(t, []entry{{ID: "Abcd1234", Name: "app/KEY", Ciphertext: ciphertext}})
	output, err := captureResolveOutput(t, []string{"app/KEY"})
	if err != nil || output != value+"\n" {
		t.Fatalf("explicit plaintext mode: output %q, error %v", output, err)
	}
	for _, args := range [][]string{
		{"app/KEY", "--exec", "true"},
		{"app/KEY", "--exec", "sh", "-c", `test "$JT_SECRET" = synthetic-resolve-test-secret`},
		{"app/KEY", "--env", "TOKEN", "--exec", "sh", "-c", `test "$TOKEN" = synthetic-resolve-test-secret`},
	} {
		output, err := captureResolveOutput(t, args)
		if err != nil || output != "" {
			t.Fatalf("valid exec mode %q: output %q, error %v", args, output, err)
		}
	}
}

func TestResolveEnvRejectsInvalidNameWithoutExposingSecret(t *testing.T) {
	const value = "synthetic-resolve-test-secret"
	ciphertext, err := seal(bytes.Repeat([]byte{1}, 32), value)
	if err != nil {
		t.Fatal(err)
	}
	setup(t, []entry{{ID: "Abcd1234", Name: "app/KEY", Ciphertext: ciphertext}})
	for _, args := range [][]string{
		{"app/KEY", "--env"},
		{"app/KEY", "--env", "--exec"},
		{"app/KEY", "--env", "--env"},
		{"app/KEY", "--env", ""},
		{"app/KEY", "--env", "BAD-NAME"},
		{"app/KEY", "--env", "TOKEN", "--env", "--exec"},
		{"app/KEY", "--env", "--exec", "true"},
		{"app/KEY", "--env", "", "--exec", "true"},
		{"app/KEY", "--env", "BAD-NAME", "--exec", "true"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output, err := captureResolveOutput(t, args)
			if err == nil {
				t.Error("expected invalid or missing environment name error")
			}
			if output != "" {
				t.Errorf("invalid --env emitted output: %q", output)
			}
		})
	}
}
