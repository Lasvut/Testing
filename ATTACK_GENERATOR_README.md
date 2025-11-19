# Attack Generator

## Overview

The Attack Generator is a demonstration tool that automatically generates simulated attacks to populate the WAF monitor logs. This is useful for demonstrations, testing, and showcasing the WAF's detection capabilities.

## Features

- **Automatic Attack Generation**: Generates random attacks every 30 seconds (configurable)
- **Multiple Attack Types**:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
- **Background Operation**: Runs in a separate thread without blocking the main application
- **Real Attack Patterns**: Uses realistic attack payloads from security databases

## Usage

### Automatic Startup (Integrated)

The attack generator starts automatically when you run the Flask application:

```bash
python3 app.py
```

You'll see output like:
```
======================================================================
STARTING WAF SYSTEM
======================================================================
🚀 Starting attack generator (interval: 30s)
   This will simulate attacks for demo purposes
   Check /monitor to see blocked attacks
======================================================================
```

### Manual Control via API

You can control the attack generator through API endpoints:

**Start Generator:**
```bash
curl -X POST http://localhost:5000/api/attack-generator/start
```

**Stop Generator:**
```bash
curl -X POST http://localhost:5000/api/attack-generator/stop
```

**Check Status:**
```bash
curl http://localhost:5000/api/attack-generator/status
```

### Standalone Mode

You can also run the attack generator as a standalone script:

```bash
python3 attack_generator.py --url http://localhost:5000 --interval 30
```

**Options:**
- `--url`: Base URL of the target application (default: http://localhost:5000)
- `--interval`: Seconds between attacks (default: 30)

**Example:**
```bash
# Generate attacks every 10 seconds
python3 attack_generator.py --interval 10

# Target a different server
python3 attack_generator.py --url http://example.com:8080 --interval 60
```

## Attack Patterns

The generator includes realistic attack patterns for:

### SQL Injection
- `' OR '1'='1`
- `' UNION SELECT * FROM users--`
- `1'; DROP TABLE users;--`
- `admin'--`
- And more...

### Cross-Site Scripting (XSS)
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(document.cookie)>`
- `<iframe src=javascript:alert(1)>`
- And more...

### Command Injection
- `; cat /etc/passwd`
- `| ls -la`
- `&& whoami`
- `` `id` ``
- And more...

### Path Traversal
- `../../../../etc/passwd`
- `../../../windows/system32/config/sam`
- `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- And more...

## Monitoring Attacks

Once the attack generator is running:

1. Navigate to `/monitor` in your web browser
2. You'll see attacks being blocked in real-time
3. The logs will show the attack type, payload, and timestamp
4. Statistics will update automatically

## Configuration

To change the attack interval, modify the initialization in `app.py`:

```python
attack_gen = AttackGenerator(base_url='http://localhost:5000', interval=30)
```

Change `interval=30` to your desired number of seconds between attacks.

## Safety Notes

⚠️ **Important:**
- This tool is for **demonstration purposes only**
- Only use against your own systems or with explicit permission
- Never use against production systems without authorization
- The attacks are designed to be blocked by the WAF

## Implementation Details

The attack generator:
1. Runs in a background daemon thread
2. Randomly selects an attack type and payload
3. Sends GET requests with malicious parameters
4. Logs whether the attack was blocked (403) or passed
5. Waits for the configured interval before the next attack

## Example Output

```
[14:23:45] ✅ Attack blocked: SQL on /search?query=' OR '1'='1...
[14:24:15] ✅ Attack blocked: XSS on /comment?message=<script>alert(1)</script>...
[14:24:45] ✅ Attack blocked: CMD on /exec?cmd=; cat /etc/passwd...
[14:25:15] ✅ Attack blocked: TRAVERSAL on /download?file=../../../../etc/passwd...
```

## Troubleshooting

**Generator not starting:**
- Ensure Flask application is running on the correct port
- Check for connection errors in the console

**Attacks not being logged:**
- Verify the WAF middleware is enabled
- Check database connection
- Ensure proper session authentication

**Too many attacks:**
- Increase the interval time
- Stop the generator with the stop endpoint

## License

This tool is part of the WAF System and is intended for educational and demonstration purposes only.
