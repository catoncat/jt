# jt

`jt` is a single-binary encrypted secret reference engine. Values are AES-GCM encrypted with a 32-byte local key; the Git vault contains ciphertext, masked previews, and plaintext metadata such as names and descriptions. Never put secret values in names or descriptions.

## Install and initialize

```sh
curl -fsSL https://raw.githubusercontent.com/catoncat/jt/main/install.sh | sh
```

For sync with a new vault, first create an empty private Git repository, then use its URL:

```sh
jt init --repo <YOUR_PRIVATE_VAULT_GIT_URL>
jt sync
```

On a fresh setup, `jt init` without `--repo` creates a local Git repository but does not add an `origin`, so skip `jt sync` until one is configured. To connect that local-only vault later, add an empty private remote with `git -C <VAULT_DIR> remote add origin <YOUR_PRIVATE_VAULT_GIT_URL>` before syncing.

For an existing vault repository, clone it into the chosen vault directory and point `jt` at the clone, using the matching local master-key file:

```sh
git clone <YOUR_PRIVATE_VAULT_GIT_URL> <VAULT_DIR>
jt init --vault <VAULT_DIR> --key <PATH_TO_EXISTING_MASTER_KEY>
jt sync
```

The key file must be the existing 32-byte key for a vault that already contains `vault.json`; `jt` will not generate a replacement key for it.

The installer downloads a published GitHub release; a change on `main` does not publish a release. To build this source version (0.3.0), use Go 1.24 or newer and `go build -o bin/jt ./cmd/jt`. Check `jt version` on every client before enabling descriptions.

Set `JT_VAULT_DIR` to the checked-out private vault and `JT_KEY_FILE` to a `0600` local master key when using a non-default layout. Copy the master key to each trusted machine out of band; never commit it to the vault.

## Use

```sh
jt add myapp/OPENAI_API_KEY --description 'Production API access; owner: platform team'
jt describe myapp/OPENAI_API_KEY 'Staging API access; owner: platform team'
jt describe jt://secret/Abcd1234 ''  # clear the description, without changing the secret
jt ls
jt ls --json                      # id, ref, name, description, preview, timestamps; never ciphertext
jt ls 'platform team'              # search name, description, or ID
jt status                         # local vault state: uncommitted changes / commits not pushed
jt resolve jt://secret/<id> --exec env VAR_NAME
jt env myapp -- your-command
```

`jt describe <name-or-ref> <description>` edits metadata only: it does not read stdin, decrypt or re-encrypt the secret, or change the ID, name, preview, or creation time. Changing the description updates `updated_at`; writing the same description is a no-op. Pass a quoted empty string to clear it. Descriptions support Unicode, including Chinese, and whitespace is preserved.

`jt add` and `jt set` accept optional `--description TEXT` or `--description=TEXT`. `set` still reads a replacement secret from stdin (or `--from-clipboard`); omitting `--description` preserves the existing description, and `--description=''` clears it. Use `describe` when only changing the description. Use the equals form for descriptions starting with a dash. Flags may come before or after the name; use `--` before a name starting with a dash. Unknown, duplicate, and missing-value flags are rejected; `--id` is supported only by `add`.

`jt env <namespace> -- command` decrypts the namespace entries inside `jt` and injects them only into the child process. Secret values are not printed by `jt` and are not passed through the calling agent's context. Descriptions never become environment variables. Use `jt sync` after changing the vault to pull or push encrypted records and their metadata.

## Vault compatibility

- This version reads both v1 and v2 vaults. Reading or editing a v1 vault without a nonempty description keeps it at v1
- The first saved nonempty description upgrades that vault to v2 atomically with the metadata change. Existing IDs and ciphertext are preserved. No separate metadata file is needed
- v0.2.0 rejects v2 vaults. Its `add`, `set`, `mv`, `rm`, `ls`, `resolve`, and `env` cannot operate on them. Upgrade **all** clients, background jobs, and integrations before adding the first description. Old `sync` can transport the file but does not make the old client v2-capable
- Clearing every description or deleting entries does **not** downgrade the vault. Do not manually lower the version: older clients would discard description fields when rewriting it
- Descriptions are plaintext, synced Git metadata, including in Git history. Clearing a description does not erase historical copies. Use only verified, non-secret purpose/environment/owner notes, never passwords or tokens

There is no automatic migration at startup or installation. Test the new binary against a temporary vault before upgrading your active clients.

For scripts and the sync UI, see [Metadata integration](docs/metadata-integration.md). See `jt help` for the complete command list.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
make cross
```

Tests use temporary keys, vaults, and local Git remotes; they do not need or modify a real vault.

## License

MIT, see [LICENSE](LICENSE).
