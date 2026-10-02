package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupSyncRemote(t *testing.T) (string, string, string) {
	t.Helper()
	dir, _ := setup(t, []entry{{ID: "AAAAAAAA", Name: "app/KEY", Ciphertext: "synthetic"}})
	remote := t.TempDir()
	git(t, remote, "init", "--bare")
	git(t, dir, "init")
	git(t, dir, "config", "user.name", "Test")
	git(t, dir, "config", "user.email", "test@example.invalid")
	git(t, dir, "add", "vault.json")
	git(t, dir, "commit", "-m", "initial")
	git(t, dir, "remote", "add", "origin", remote)
	git(t, dir, "push", "-u", "origin", "HEAD")
	other := t.TempDir()
	git(t, other, "clone", remote, ".")
	return dir, remote, other
}

func writeSyncVault(t *testing.T, dir, name string) {
	t.Helper()
	data := []byte(`{"version":1,"secrets":[{"id":"AAAAAAAA","name":"` + name + `","ciphertext":"synthetic"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "vault.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func syncGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitOutput(dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return out
}

func TestSyncStopsOnAutostashConflict(t *testing.T) {
	dir, remote, other := setupSyncRemote(t)
	writeSyncVault(t, other, "remote/KEY")
	git(t, other, "commit", "-am", "remote change")
	git(t, other, "push", "origin", "HEAD")
	remoteHead := syncGitOutput(t, remote, "rev-parse", "HEAD")
	remoteVault := syncGitOutput(t, remote, "show", "HEAD:vault.json")
	writeSyncVault(t, dir, "local/KEY")

	err := syncVault(nil)
	if err == nil || !strings.Contains(err.Error(), "unresolved Git conflicts") {
		t.Fatalf("expected conflict error, got %v", err)
	}
	if got := syncGitOutput(t, remote, "rev-parse", "HEAD"); got != remoteHead {
		t.Fatalf("sync pushed a conflict: remote HEAD changed from %s to %s", remoteHead, got)
	}
	if got := syncGitOutput(t, remote, "show", "HEAD:vault.json"); got != remoteVault {
		t.Fatal("remote vault changed after conflict")
	}
	if got := syncGitOutput(t, dir, "rev-parse", "HEAD"); got != remoteHead {
		t.Fatal("sync committed unresolved conflict markers")
	}
	unmerged := syncGitOutput(t, dir, "ls-files", "--unmerged")
	if unmerged == "" {
		t.Fatal("conflicted index should remain available for manual resolution")
	}
	if got := syncGitOutput(t, dir, "stash", "show", "-p"); !strings.Contains(got, "local/KEY") {
		t.Fatal("local update is not preserved in the autostash")
	}

	// A second sync must not stage an already-conflicted working tree either.
	before, err := os.ReadFile(filepath.Join(dir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := syncVault(nil); err == nil || !strings.Contains(err.Error(), "unresolved Git conflicts") {
		t.Fatalf("expected conflict error on retry, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || syncGitOutput(t, dir, "ls-files", "--unmerged") != unmerged {
		t.Fatal("retry changed conflict data")
	}
}

func TestSyncStillPushesUnconflictedChanges(t *testing.T) {
	dir, remote, _ := setupSyncRemote(t)
	writeSyncVault(t, dir, "local/KEY")
	if err := syncVault(nil); err != nil {
		t.Fatal(err)
	}
	if got := syncGitOutput(t, remote, "show", "HEAD:vault.json"); !strings.Contains(got, "local/KEY") {
		t.Fatal("local update was not pushed")
	}
	if got := syncGitOutput(t, dir, "status", "--porcelain"); got != "" {
		t.Fatalf("working tree not clean: %s", got)
	}
}
