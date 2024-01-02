## WinSSHTermVaultRecovery
This Python script is a tool designed to recover the master password of a [WinSSHTerm](https://winsshterm.blogspot.com) vault using the `keyfile` from WinSSHTerms's config directory. The script iterates through a provided wordlist, attempting to decrypt the keyfile with each password.

## How is this possible?
- The WinSSHTerm vault uses a combination of a user-defined password, a static salt, and a pepper for its encryption.
- The script utilizes `PBKDF2 HMAC` with `SHA1` for key derivation and `AES` in `CBC` mode for decryption.
- The keyfile is decrypted using each password from the wordlist in conjunction with the static salt and pepper until the correct password is found.
- The `SALT` and `SUFFIX` are hardcoded in the `.NET` assembly of the application, while the `PEPPER` can be dynamically derived by debugging the application.

### About WinSSHTerm
The ability to recover passwords from WinSSHTerm vaults should not be seen as a flaw in WinSSHTerm's design. It primarily highlights the crucial role of password strength. The security of encrypted data in such systems greatly depends on the complexity of the user's chosen password. Weak or common passwords are often the most significant vulnerability in these scenarios. Therefore, it's essential for users to adopt strong, unique passwords to ensure the security of their data.

## Script Usage
```bash
usage: winsshterm_vault_recovery.py [-h] [-d] keyfile wordlist_file

Recover the master password of a WinSSHTerm vault using a keyfile from the config directory.

positional arguments:
  keyfile        Path to the keyfile (encrypted master password)
  wordlist_file  Path to the wordlist file

options:
  -h, --help     show this help message and exit
  -d, --debug    Enable debug mode
```

---

*The script is for informational and educational purposes only. The author and contributors of this script are not responsible for any misuse or damage caused by this tool.* <!-- meme -->

