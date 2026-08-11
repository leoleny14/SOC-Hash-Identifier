import re
import sys
import requests

# ==============================================================================
# CONFIGURATION
# Set your VirusTotal API key here (or leave blank to skip VT lookups)
# ==============================================================================
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"


def identify_hash(hash_str: str) -> list[str]:
    """
    Evaluates a hash string against known cryptographic and credential hash patterns.
    """
    # Clean whitespace and strip single/double quotes if copied from logs
    cleaned_hash = hash_str.strip().strip("'\"")
    matches = []

    #Check formatted/salted hashes first before raw hex strings
    complex_patterns = {
        r'^\$argon2(d|i|id)\$.+$': "Argon2 (Modern Password Hash)",
        r'^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$': "Bcrypt",
        r'^\$6\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$': "SHA-512 Crypt (Linux Shadow /etc/passwd)",
        r'^\$5\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}$': "SHA-256 Crypt (Linux Shadow /etc/passwd)",
        r'^\$1\$(rounds=\d+\$)?[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$': "MD5 Crypt (FreeBSD / Cisco Type 5)",
        r'^\$8\$.+$': "Cisco Type 8 (PBKDF2-SHA256)",
        r'^\$9\$.+$': "Cisco Type 9 (Scrypt)",
        r'^\$krb5asrep\$23\$.+$': "Kerberos 5 AS-REP (AS-REP Roasting)",
        r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$': "NetNTLMv2 (Active Directory Credential Dump)",
        r'^\*[A-Fa-f0-9]{40}$': "MySQL 4.1 / 5.x (Double SHA-1)",
        r'^\$A\$[A-Fa-f0-9]{3}\$.+$': "MySQL 8.x (caching_sha2_password)"
    }

    # Test against complex patterns
    for pattern, hash_name in complex_patterns.items():
        if re.match(pattern, cleaned_hash):
            matches.append(hash_name)

    # If it matched a complex prefix, return early
    if matches:
        return matches

    # Check raw hex stings
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


def check_virustotal(file_hash: str) -> dict | None:
    """
    Queries VirusTotal API v3 for threat intelligence report on a given hash.
    Comprehensively checks malicious, suspicious, and sandbox verdicts.
    """
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "API Key not configured. Set VT_API_KEY in script."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "status": "Not Found",
                "message": "Hash NOT FOUND in VirusTotal. (Common for NTLM password hashes or clean un-uploaded files)."
            }
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API Key."}
        elif response.status_code != 200:
            return {"error": f"HTTP Error {response.status_code}: {response.reason}"}

        json_data = response.json()
        attrs = json_data.get("data", {}).get("attributes", {})

        # Extract Threat Stats (Including Suspicious)
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Check Sandbox Verdicts if AV engines missed it
        sandbox_verdicts = attrs.get("sandbox_verdicts", {})
        sandbox_malicious = False
        for sandbox, verdict in sandbox_verdicts.items():
            if verdict.get("category") in ["malicious", "suspicious"]:
                sandbox_malicious = True
                break

        # Calculate Overall Threat Status
        is_threat = (malicious > 0) or (suspicious > 0) or sandbox_malicious

        # Metadata
        suggested_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "Unclassified")
        type_description = attrs.get("type_description", "Unknown File Type")
        meaningful_name = attrs.get("meaningful_name", "N/A")

        # Top Engine Results
        results = attrs.get("last_analysis_results", {})
        flagged_engines = []

        # Prioritize major engines for output
        priority_engines = ["Microsoft", "Kaspersky", "CrowdStrike", "Sophos", "Symantec", "BitDefender"]

        for engine, data in results.items():
            cat = data.get("category")
            if cat in ["malicious", "suspicious"]:
                flagged_engines.append(f"{engine} ({cat.upper()}): {data.get('result')}")

        return {
            "status": "Found",
            "is_threat": is_threat,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "detection_ratio": f"{malicious + suspicious}/{total}",
            "type_description": type_description,
            "meaningful_name": meaningful_name,
            "suggested_label": suggested_label,
            "flagged_engines": flagged_engines[:5] if flagged_engines else ["No specific engine signatures detailed."]
        }

    except requests.RequestException as e:
        return {"error": f"Network request failed: {str(e)}"}


def main():
    print("=" * 70)
    print("  SOC ANALYST LAB: ADVANCED HASH IDENTIFIER & VIRUSTOTAL TRIAGE  ")
    print("=" * 70)

    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("[!] Note: VirusTotal API Key is missing. Live threat lookups are disabled.")
        print("[!] Add your free API key to the 'VT_API_KEY' variable to enable VT integration.")

    while True:
        user_input = input("\nEnter a hash to analyze (or 'q' to quit): ").strip()

        if user_input.lower() in ['q', 'quit', 'exit']:
            print("\n[+] Exiting Hash Identifier. Stay safe!")
            sys.exit(0)

        if not user_input:
            print("[-] Input cannot be empty.")
            continue

        # 1. Structural Identification
        results = identify_hash(user_input)

        # Truncate long hashes for cleaner terminal output
        display_hash = user_input[:40] + "..." if len(user_input) > 40 else user_input

        print(f"\n[ STRUCTURAL MATCH FOR ]: {display_hash}")
        print(f"[-] Character Length: {len(user_input)}")
        print("[-] Possible Format Match(es):")
        for match in results:
            print(f"    └──> {match}")

        # 2. VirusTotal Intelligence Enrichment
        cleaned = user_input.strip().strip("'\"")

        # We only query VirusTotal if the hash is a standard file hash length (32, 40, or 64)
        is_file_hash = len(cleaned) in [32, 40, 64] and re.match(r'^[a-fA-F0-9]+$', cleaned)

        if is_file_hash and VT_API_KEY and VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY_HERE":
            print("\n[ VIRUSTOTAL THREAT INTEL TRIAGE ]")
            print("[-] Querying VirusTotal API v3...")

            vt_result = check_virustotal(cleaned)

            if "error" in vt_result:
                print(f"    └──> [ERROR]: {vt_result['error']}")

            elif vt_result.get("status") == "Not Found":
                print(f"    └──> {vt_result['message']}")

            else:
                verdict = "MALICIOUS / SUSPICIOUS 🚨" if vt_result["is_threat"] else "CLEAN / BENIGN ✅"
                print(f"    └──> Verdict: {verdict}")

                if vt_result["is_threat"]:
                    print(f"    └──> Detection Score: {vt_result['detection_ratio']} AV Engines Flagged as Threat")
                    print(f"    └──> File Type: {vt_result['type_description']}")
                    print(f"    └──> Sample Name: {vt_result['meaningful_name']}")
                    print(f"    └──> Primary Threat Label: {vt_result['suggested_label']}")
                    print("    └──> Key AV Detections:")
                    for det in vt_result['flagged_engines']:
                        print(f"          • {det}")


if __name__ == "__main__":
    main()
