# jt

`jt` is a single-binary encrypted secret reference engine. Values are AES-GCM encrypted with a 32-byte local key; the Git vault contains ciphertext and masked metadata only.

## Install and initialize

```sh
curl -fsSL https://raw.githubusercontent.com/catoncat/jt/main/install.sh | sh
jt init
jt sync
```

Set `JT_VAULT_DIR` to the checked-out private vault and `JT_KEY_FILE` to a `0600` local master key when using a non-default layout. Copy the master key to each trusted machine out of band; never commit it to the vault.

## Use

```sh
jt add mom/OPENAI_API_KEY
jt ls
jt resolve jt://secret/<id> --exec env VAR_NAME
jt env mom -- your-command
```

`jt env <namespace> -- command` decrypts the namespace entries inside `jt` and injects them only into the child process. Secret values are not printed by `jt` and are not passed through the calling agent's context. Use `jt sync` after changing the vault to pull or push encrypted records.

See `jt help` for the complete command list.
