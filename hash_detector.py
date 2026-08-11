import re
import sys

def identify_hash(hash_str: str) -> list[str]:
    """
    Evaluates a hash string against known cryptographic and credential hash patterns.
    """
    # Clean whitespace and strip single/double quotes if copied from logs
    cleaned_hash = hash_str.strip().strip("'\"")
    matches = []

    # 1. COMPLEX & FORMATTED HASHES (Evaluated first)
    complex_patterns = {
        r'^\$argon2(d|i|id)\$.+$': "Argon2 (Modern Password Hash)",
        r'^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$': "Bcrypt",

        # Linux shadow hashes (accommodates optional 'rounds=' parameter)
        r'^\$6\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$': "SHA-512 Crypt (Linux Shadow /etc/passwd)",
        r'^\$5\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}$': "SHA-256 Crypt (Linux Shadow /etc/passwd)",
        r'^\$1\$(rounds=\d+\$)?[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$': "MD5 Crypt (FreeBSD / Cisco Type 5)",

        r'^\$8\$.+$': "Cisco Type 8 (PBKDF2-SHA256)",
        r'^\$9\$.+$': "Cisco Type 9 (Scrypt)",
        r'^\$krb5asrep\$23\$.+$': "Kerberos 5 AS-REP (AS-REP Roasting)",

        # NetNTLMv2 format from Responder/Impacket (User::Domain:Challenge:NTProof:Response)
        r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$': "NetNTLMv2 (Active Directory Credential Dump)",

        # MySQL formats
        r'^\*[A-Fa-f0-9]{40}$': "MySQL 4.1 / 5.x (Double SHA-1)",
        r'^\$A\$[A-Fa-f0-9]{3}\$.+$': "MySQL 8.x (caching_sha2_password)"
    }

    # Test against complex patterns
    for pattern, hash_name in complex_patterns.items():
        if re.match(pattern, cleaned_hash):
            matches.append(hash_name)

    # If it matched a complex prefix, return early so it doesn't conflict with hex rules
    if matches:
        return matches

    # 2. RAW HEXADECIMAL HASHES (Evaluated second based on length)
    if re.match(r'^[a-fA-F0-9]+$', cleaned_hash):
        length = len(cleaned_hash)

        if length == 32:
            matches.extend(["MD5 (File/Malware)", "NTLM (Windows AD Credential)"])
        elif length == 40:
            matches.extend(["SHA-1", "RIPEMD-160"])
        elif length == 56:
            matches.append("SHA-224")
        elif length == 64:
            matches.extend(["SHA-256 (Common Malware IOC)", "SHA3-256"])
        elif length == 96:
            matches.extend(["SHA-384", "SHA3-384"])
        elif length == 128:
            matches.extend(["SHA-512", "SHA3-512"])

    return matches if matches else ["Unknown Hash Type / Unrecognized Format"]


def main():
    print("=" * 60)
    print("    SOC ANALYST LAB: ADVANCED HASH IDENTIFIER TOOL    ")
    print("=" * 60)

    while True:
        user_input = input("\nEnter a hash to analyze (or 'q' to quit): ").strip()

        if user_input.lower() in ['q', 'quit', 'exit']:
            print("\n[+] Exiting Hash Identifier. Stay safe!")
            sys.exit(0)

        if not user_input:
            print("[-] Input cannot be empty.")
            continue

        results = identify_hash(user_input)

        # Truncate long hashes for cleaner terminal output
        display_hash = user_input[:40] + "..." if len(user_input) > 40 else user_input

        print(f"\n[ RESULTS FOR ]: {display_hash}")
        print(f"[-] Character Length: {len(user_input)}")
        print("[-] Possible Match(es):")
        for match in results:
            print(f"    └──> {match}")

# This must be outside the main() function and loop
if __name__ == "__main__":
    main()
