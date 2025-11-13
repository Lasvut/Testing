RULES = {
    "SQL Injection": [
        # Union-based injection
        r"(?i)(\bunion\b.{1,100}?\bselect\b)",
        r"(?i)(\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)",
        
        # Boolean-based blind
        r"(?i)((\bor|\band)\b\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*['\"]?)",
        r"(?i)(['\"]?\s*(or|and)\s*['\"]?[0-9]+['\"]?\s*[=<>]+\s*['\"]?[0-9]+)",
        
        # Time-based blind
        r"(?i)(benchmark\s*\(\s*\d+)",
        r"(?i)(sleep\s*\(\s*\d+)",
        r"(?i)(waitfor\s+delay\s+['\"])",
        r"(?i)(pg_sleep\s*\()",
        
        # Stacked queries
        r"(?i)(;.{0,10}?(drop|alter|create|truncate|insert|update|delete|exec))",
        
        # Comment injection
        r"(?i)(['\"]?\s*(--|#|\/\*))",
        r"(?i)(\/\*!?\d{0,5}\s*(?:union|select|insert|update|delete|drop|create|alter))",
        
        # Information gathering
        r"(?i)(information_schema|sysobjects|syscolumns|mysql\.user)",
        r"(?i)(\btable_schema\b|\btable_name\b)",
        
        # Functions and procedures
        r"(?i)(\bexec(\s|\+)+(s|x)p\w+)",
        r"(?i)(xp_cmdshell|sp_executesql|sp_oacreate)",
        
        # Encoding bypasses
        r"(?i)(0x[0-9a-f]{2,})",  # Hex encoding
        r"(?i)(char\s*\(\s*\d+\s*\))",  # CHAR function
        r"(?i)(ascii\s*\(\s*substr)",  # ASCII substring
        r"(?i)(unhex\s*\(|hex\s*\()",
        
        # Error-based
        r"(?i)(extractvalue\s*\(|updatexml\s*\()",
        r"(?i)(exp\s*\(~\s*\(|floor\s*\(rand\s*\()",
        
        # Out-of-band
        r"(?i)(load_file\s*\(|into\s+outfile)",
    ],
    
    "Cross-Site Scripting": [
        # Script tags
        r"(?i)(<script[^>]*>[\s\S]*?<\/script>)",
        r"(?i)(<script[^>]*>)",
        
        # Event handlers
        r"(?i)(on\w+\s*=\s*['\"]?[^'\">]*['\"]?)",
        r"(?i)(<[^>]+\s+on(load|error|click|mouse\w+|focus|blur|change|submit)\s*=)",
        
        # JavaScript protocol
        r"(?i)(javascript:)",
        r"(?i)(vbscript:)",
        
        # Data URIs
        r"(?i)(data:text\/html[^,]*,[\s\S]*<script)",
        r"(?i)(data:image\/svg\+xml[^,]*,[\s\S]*<script)",
        
        # DOM manipulation
        r"(?i)(document\.(cookie|write|writeln|location|domain))",
        r"(?i)(window\.(location|eval|execScript|setTimeout|setInterval))",
        r"(?i)(\.innerHTML\s*=)",
        
        # HTML injection
        r"(?i)(<iframe[^>]*>)",
        r"(?i)(<embed[^>]*>)",
        r"(?i)(<object[^>]*>)",
        r"(?i)(<applet[^>]*>)",
        r"(?i)(<meta[^>]*>)",
        
        # Image tags with XSS
        r"(?i)(<img[^>]*src[^>]*onerror)",
        r"(?i)(<img[^>]*src\s*=\s*javascript:)",
        
        # SVG-based XSS
        r"(?i)(<svg[^>]*>[\s\S]*?<script)",
        r"(?i)(<svg[^>]*onload\s*=)",
        
        # CSS expression
        r"(?i)(expression\s*\([^)]*\))",
        r"(?i)(behavior\s*:\s*url)",
        r"(?i)(@import\s+['\"]?javascript:)",
        
        # XML/RSS XSS
        r"(?i)(<\?xml[^>]*>[\s\S]*?<script)",
        
        # Form injection
        r"(?i)(<form[^>]*action\s*=)",
        r"(?i)(<input[^>]*type\s*=\s*['\"]?hidden)",
        
        # Uncommon tags
        r"(?i)(<marquee[^>]*>)",
        r"(?i)(<bgsound[^>]*>)",
        r"(?i)(<link[^>]*>)",
    ],
    
    "Command Injection": [
        # Shell command chaining
        r"(;|\||`|\$\(|\$\{).{0,20}?(cat|ls|wget|curl|nc|bash|sh|cmd|powershell|whoami|id|pwd)",
        
        # Common Unix commands
        r"(?i)(\b(cat|tac|nl|od|base64|xxd)\b.{0,50}?(\/etc\/passwd|\/etc\/shadow))",
        r"(?i)(\b(ls|dir|find)\b\s+(-la|-R))",
        r"(?i)(\buname\b\s*-a)",
        
        # Network commands
        r"(?i)(\b(wget|curl|fetch|lynx)\b.{1,100}?(http|ftp))",
        r"(?i)(\bnc\b\s+(-l|-e|\.exec))",
        r"(?i)(\btelnet\b.{1,50}?\d+)",
        
        # File operations
        r"(?i)(\b(rm|del|rmdir)\b\s+(-rf|-r|-f))",
        r"(?i)(\b(chmod|chown|chgrp)\b)",
        r"(?i)(\b(cp|mv|dd)\b.{1,100}?\/dev)",
        
        # Process commands
        r"(?i)(\b(ps|top|kill|killall|pkill)\b)",
        r"(?i)(\b(nohup|disown)\b)",
        
        # Shell invocation
        r"(?i)(\/bin\/(ba)?sh)",
        r"(?i)(cmd\.exe|cmd\s+\/c)",
        r"(?i)(powershell\.exe|pwsh)",
        r"(?i)(\bperl\b\s+-e)",
        r"(?i)(\bpython\b\s+(-c|<))",
        r"(?i)(\bruby\b\s+-e)",
        
        # Privilege escalation
        r"(?i)(\bsudo\b|\bsu\b\s+(-|root))",
        r"(?i)(\bchroot\b)",
        
        # Environment manipulation
        r"(?i)(PATH\s*=|LD_PRELOAD\s*=)",
        r"(?i)(\bexport\b.{1,50}?(PATH|LD_PRELOAD))",
    ],
    
    "Directory Traversal": [
        # Basic traversal
        r"(\.\.\/|\.\.\\){2,}",
        r"(\.\.;\/|\.\.;\\)",
        
        # Encoded traversal
        r"(%2e%2e[\/\\]|%252e%252e[\/\\])",
        r"(\.\.%2f|\.\.%5c)",
        r"(%c0%ae%c0%ae\/|%c0%ae%c0%ae\\)",
        
        # Unicode encoding
        r"(\.\.\u2216|\.\.\u2215)",
        r"(\x2e\x2e[\/\\])",
        
        # Sensitive file access
        r"(?i)(\/etc\/(passwd|shadow|hosts|group|issue))",
        r"(?i)(\/proc\/self\/(environ|cmdline|fd))",
        r"(?i)(c:\\windows\\(system32|win\.ini|boot\.ini))",
        r"(?i)(\/var\/(log|mail|www))",
        
        # Application files
        r"(?i)(web\.config|\.htaccess|\.htpasswd)",
        r"(?i)(wp-config\.php|configuration\.php)",
        r"(?i)(database\.yml|secrets\.yml)",
    ],
    
    "Remote File Inclusion": [
        # Protocol wrappers
        r"(?i)(php:\/\/(filter|input|output|fd|memory|temp|stdin|stdout|stderr))",
        r"(?i)(file:\/\/|zip:\/\/|zlib:\/\/|data:\/\/)",
        r"(?i)(expect:\/\/|glob:\/\/|phar:\/\/)",
        r"(?i)(ogg:\/\/|rar:\/\/)",
        
        # Remote URL inclusion
        r"(?i)(https?:\/\/[^\s\"'<>]+\.(txt|php|asp|aspx|jsp|xml))",
        r"(?i)(ftp:\/\/[^\s\"'<>]+)",
        
        # Null byte injection
        r"(%00|\\0|0x00)",
        r"(?i)(\.php%00|\.asp%00|\.jsp%00)",
        
        # Filter bypass
        r"(?i)(php:\/\/filter\/convert\.base64-encode\/resource=)",
        r"(?i)(php:\/\/filter\/read=string\.rot13\/resource=)",
    ],
    
    "LDAP Injection": [
        # LDAP filter manipulation
        r"(\(\s*[|&]\s*\()",
        r"(\)\s*\(\s*[|&])",
        r"(\*\s*\)\s*\()",
        r"(\(\s*\|\s*\(.*\)\s*\))",
        
        # LDAP special characters
        r"(\(\s*\*\s*\))",
        r"(~=|>=|<=)",
    ],
    
    "XML/XXE Injection": [
        # External entity
        r"(?i)(<!ENTITY[^>]+SYSTEM)",
        r"(?i)(<!ENTITY[^>]+PUBLIC)",
        
        # DOCTYPE declaration
        r"(?i)(<!DOCTYPE[^>]+\[)",
        
        # Parameter entities
        r"(?i)(%\w+;)",
        
        # CDATA abuse
        r"(?i)(<!\[CDATA\[[\s\S]*?\]\]>)",
    ],
    
    "Server-Side Request Forgery": [
        # Internal IPs
        r"(https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0))",
        r"(https?:\/\/(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.))",
        r"(https?:\/\/\[::1\])",
        
        # Cloud metadata
        r"(?i)(169\.254\.169\.254)",
        r"(?i)(metadata\.google\.internal)",
        r"(?i)(instance-data)",
    ],
    
    "HTTP Header Injection": [
        # CRLF injection
        r"(%0d%0a|\\r\\n|%0a|\\n)",
        r"(?i)(Set-Cookie:|Location:|Content-Type:)",
        
        # Response splitting
        r"(\r\n\r\n|\n\n)",
    ],
    
    "NoSQL Injection": [
        # MongoDB
        r"(?i)(\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin)",
        r"(?i)(\$where|\$regex|\$exists)",
        
        # JSON injection
        r"(?i)(\"\\s*\$ne\\s*\"\\s*:\\s*null)",
    ],
}


def get_rule_sources():
    """Return information about rule sources"""
    return {
        "OWASP CRS": "https://github.com/coreruleset/coreruleset",
        "Cloudflare": "https://github.com/cloudflare/lua-resty-waf",
        "AWS WAF": "https://docs.aws.amazon.com/waf/latest/developerguide/",
        "ModSecurity": "https://github.com/SpiderLabs/ModSecurity",
    }


def get_rule_statistics():
    """Get statistics about the ruleset"""
    total_rules = sum(len(patterns) for patterns in RULES.values())
    return {
        "total_categories": len(RULES),
        "total_rules": total_rules,
        "rules_per_category": {k: len(v) for k, v in RULES.items()}
    }


if __name__ == "__main__":
    stats = get_rule_statistics()
    print("=" * 60)
    print("WAF RULESET STATISTICS")
    print("=" * 60)
    print(f"Total Categories: {stats['total_categories']}")
    print(f"Total Rules: {stats['total_rules']}")
    print("\nRules per category:")
    for category, count in stats['rules_per_category'].items():
        print(f"  {category:30s}: {count:3d} rules")
    
    print("\n" + "=" * 60)
    print("SOURCES:")
    print("=" * 60)
    for source, url in get_rule_sources().items():
        print(f"  {source}: {url}")