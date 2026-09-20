/* Obfuscation & Packing YARA Rules */

rule Obfuscation_Dense_Hex_Escapes {
    meta:
        prefix = "SUSPICIOUS_OBFUSCATION"
        label = "Dense Hex Escape Sequences"
        category = "obfuscation"
        severity = 70
        description = "Dense string of hexadecimal escape characters commonly used to conceal shellcode or URLs"
    strings:
        // Threshold raised from 8 to 16: common binary file-signature checks
        // (PNG's 8-byte magic number, JPEG, GIF, ...) sit right at 8 and are
        // completely benign — confirmed false positive on real-world `discord-py`
        // (`data.startswith(b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a')`, an image-type
        // sniff). Real obfuscated payloads run far longer: the confirmed-malicious
        // sample that motivated this rule ("bettercolor") has runs of 47 and 105
        // consecutive escapes, comfortably clear of 16 either way.
        $ = /(\\x[0-9a-fA-F]{2}){16,}/ ascii
    condition:
        any of them
}

rule Obfuscation_Layered_Decode_Decompress {
    meta:
        prefix = "SUSPICIOUS_OBFUSCATION"
        label = "Layered Base64 and Decompress Pipeline"
        category = "decode"
        severity = 80
        description = "Base64 decode immediately piped into compression decompression or bytecode loader"
    strings:
        // NOTE: a `b64decode(...).decode()/.strip()` sub-pattern used to be here
        // too, but "decode a base64 string into text" is one of the most common,
        // completely benign idioms in real code (parsing a JWT claim, a webhook
        // payload, an API response) — confirmed false positives on real-world
        // `c7n-azure` (decoding an Azure event) and `spotapi` (decoding a JSON
        // config blob), neither remotely malicious. Removed rather than narrowed:
        // there's no regex that keeps "flag base64-decoded text" while excluding
        // ordinary use, because the two are the same thing. The remaining
        // patterns below are much more specific — decoding *into* a compressed
        // or marshaled/executable form is genuinely rare outside payload staging.
        $py2 = /zlib\.decompress\(\s*(base64\.)?b64decode/ ascii
        $py3 = /marshal\.loads\(\s*(base64\.)?b64decode/ ascii
        $py4 = /bz2\.decompress\(\s*(base64\.)?b64decode/ ascii
        $js1 = /Buffer\.from\([^,]+,\s*['"]base64['"]\)\.toString\(/ ascii
        $js2 = /zlib\.(gunzipSync|inflateSync)\(\s*Buffer\.from/ ascii
    condition:
        any of them
}

rule Obfuscation_JS_Array_Lookup {
    meta:
        prefix = "SUSPICIOUS_OBFUSCATION"
        label = "Obfuscator Dictionary Lookup Pattern"
        category = "obfuscation"
        severity = 65
        description = "Dictionary lookup array and indexer pattern used by JavaScript obfuscators"
    strings:
        $arr = /var\s+_0x[a-f0-9]{4,6}\s*=\s*\[.*\];\s*\(function\s*\(/ ascii
        $dict_lookup = /_0x[a-f0-9]{4,6}\(\s*0x[a-f0-9]+\s*\)/ ascii
    condition:
        any of them
}

rule Obfuscation_Invisible_Unicode_Steganography {
    meta:
        prefix = "SUSPICIOUS_OBFUSCATION"
        label = "Invisible Unicode Steganography / Bidi Override"
        category = "obfuscation"
        severity = 85
        description = "Zero-width spaces or bidirectional overrides used to disguise code"
    strings:
        // Zero-width space sequences (\u200B, \u200C, \u200D in UTF-8: E2 80 8B, E2 80 8C, E2 80 8D)
        $zw1 = { E2 80 8B }
        $zw2 = { E2 80 8C }
        $zw3 = { E2 80 8D }
        // Right-to-Left Override (\u202E in UTF-8: E2 80 AE)
        $bidi = { E2 80 AE }
    condition:
        (#zw1 + #zw2 + #zw3 >= 10) or $bidi
}
