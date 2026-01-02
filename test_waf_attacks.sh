#!/bin/bash
# WAF Penetration Testing Script
# Tests various attack vectors against the WAF

TARGET="http://localhost:5000"
echo "=========================================="
echo "WAF Penetration Testing"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TOTAL=0
BLOCKED=0
PASSED=0

test_attack() {
    local name="$1"
    local url="$2"
    TOTAL=$((TOTAL + 1))

    echo -n "Test $TOTAL: $name ... "
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

    if [ "$response" == "403" ]; then
        echo -e "${RED}BLOCKED ✓${NC} (Expected)"
        BLOCKED=$((BLOCKED + 1))
    elif [ "$response" == "200" ]; then
        echo -e "${GREEN}PASSED ✗${NC} (Vulnerability!)"
        PASSED=$((PASSED + 1))
    else
        echo -e "${YELLOW}ERROR${NC} (HTTP $response)"
    fi
}

echo "=== SQL Injection Tests ==="
test_attack "SQL - UNION SELECT" "${TARGET}/search?q=test' UNION SELECT 1,2,3--"
test_attack "SQL - OR 1=1" "${TARGET}/search?q=admin' OR '1'='1"
test_attack "SQL - DROP TABLE" "${TARGET}/search?q=test'; DROP TABLE users--"
test_attack "SQL - Time-based blind" "${TARGET}/search?q=test' AND SLEEP(5)--"
test_attack "SQL - Error-based" "${TARGET}/search?q=test' AND 1=CONVERT(int,@@version)--"
echo ""

echo "=== Cross-Site Scripting (XSS) Tests ==="
test_attack "XSS - Script tag" "${TARGET}/search?q=<script>alert(1)</script>"
test_attack "XSS - IMG onerror" "${TARGET}/search?q=<img src=x onerror=alert(1)>"
test_attack "XSS - SVG onload" "${TARGET}/search?q=<svg/onload=alert('XSS')>"
test_attack "XSS - Event handler" "${TARGET}/search?q=<body onload=alert(1)>"
test_attack "XSS - JavaScript protocol" "${TARGET}/search?q=<a href='javascript:alert(1)'>Click</a>"
echo ""

echo "=== Command Injection Tests ==="
test_attack "CMD - Semicolon" "${TARGET}/search?q=test;ls -la"
test_attack "CMD - Pipe" "${TARGET}/search?q=test|whoami"
test_attack "CMD - Backticks" "${TARGET}/search?q=test\`id\`"
test_attack "CMD - Dollar" "${TARGET}/search?q=test\$(whoami)"
test_attack "CMD - AND operator" "${TARGET}/search?q=test && cat /etc/passwd"
echo ""

echo "=== Path Traversal Tests ==="
test_attack "Path - Dot dot slash" "${TARGET}/search?q=../../../../etc/passwd"
test_attack "Path - Encoded" "${TARGET}/search?q=..%2F..%2F..%2Fetc%2Fpasswd"
test_attack "Path - Windows" "${TARGET}/search?q=..\\..\\..\\windows\\system32\\config\\sam"
echo ""

echo "=== LDAP Injection Tests ==="
test_attack "LDAP - OR filter" "${TARGET}/search?q=admin*)(&(password=*))"
test_attack "LDAP - Wildcard" "${TARGET}/search?q=*)(uid=*"
echo ""

echo "=== XML Injection Tests ==="
test_attack "XML - Entity" "${TARGET}/search?q=<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
echo ""

echo "=== Server-Side Injection Tests ==="
test_attack "SSI - Exec" "${TARGET}/search?q=<!--#exec cmd='/bin/ls' -->"
test_attack "SSI - Include" "${TARGET}/search?q=<!--#include virtual='/etc/passwd' -->"
echo ""

echo "=========================================="
echo "Test Results Summary"
echo "=========================================="
echo "Total Tests:    $TOTAL"
echo -e "Blocked (WAF):  ${RED}$BLOCKED${NC}"
echo -e "Passed (VULN):  ${GREEN}$PASSED${NC}"
echo ""
if [ $BLOCKED -eq $TOTAL ]; then
    echo -e "${GREEN}✓ WAF is working perfectly!${NC}"
    echo "All attack vectors were blocked."
elif [ $BLOCKED -gt $((TOTAL / 2)) ]; then
    echo -e "${YELLOW}⚠ WAF is partially effective${NC}"
    echo "Some attacks passed through."
else
    echo -e "${RED}✗ WAF needs improvement${NC}"
    echo "Many attacks were not blocked."
fi
echo ""
echo "Check dashboard at: ${TARGET}/dashboard"
echo "=========================================="
