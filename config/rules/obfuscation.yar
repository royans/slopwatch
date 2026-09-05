/* Obfuscation & Packing YARA Rules */

rule Obfuscation_Dense_Hex_Escapes {
    meta:
        prefix = "SUSPICIOUS_OBFUSCATION"
        label = "Dense Hex Escape Sequences"
        category = "obfuscation"
        severity = 70
        description = "Dense string of hexadecimal escape characters commonly used to conceal shellcode or URLs"
    strings:
        $ = /(\\x[0-9a-fA-F]{2}){8,}/ ascii
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
        $py1 = /b64decode\([^)]+\)\.(decode|strip)/ ascii
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
