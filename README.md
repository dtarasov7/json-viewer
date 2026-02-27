# 📊 JSON TUI Viewer — Secure Terminal JSON/JSONL Browser

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-red)](#security-features)
[![Version](https://img.shields.io/badge/Version-v1.1.0-brightgreen)](CHANGELOG.md)

<img width="1046" height="1324" alt="image" src="https://github.com/user-attachments/assets/75b13f5a-72e5-48ae-8178-0ba2d168a17d" />

A blazing-fast, secure terminal-based JSON/JSONL viewer with lazy loading, regex search, field filtering, and **built-in protection against JSON bombs and ReDoS attacks**. Perfect for exploring massive JSON datasets (millions of records) directly in your terminal.

Current version: `v1.1.0`  
Changelog: [CHANGELOG.md](CHANGELOG.md)

## ✨ Key Features

### 🔒 Security-First Design
- **JSON Bomb Protection**: Depth limits, string/number size validation
- **ReDoS Mitigation**: Regex operations timeout after 2 seconds
- **CVE-2020-10735 Protection**: Prevents hangs from maliciously long numbers
- **Device Access Blocking**: Blocks `/dev/`, `/proc/`, `/sys/` paths
- **Node Expansion Limits**: Prevents memory exhaustion (`MAX_EXPAND_NODES=100K`)

### ⚡ Performance Optimizations
- **Lazy Loading**: Only loads visible objects (handles 10M+ record files)
- **LRU Caching**: Smart object caching (200-object default)
- **Zero Memory Bloat**: Never loads entire file into RAM
- **Background Preloading**: Smooth navigation with predictive loading

### 🔍 Powerful Navigation & Search
- Tree navigation with expand/collapse (`→`/`←`, `a`/`z`, `A`/`Z`)
- Regex search with field-specific or global scope (`s`, `F`)
- Field filtering to focus on relevant data (`f`)
- Jump to object by index (`g`)
- Preserve cursor position when switching objects (`PgUp`/`PgDn`)

### 📦 Format Support
- **Standard JSON**: Single-object files
- **JSONL (JSON Lines)**: One object per line (ideal for logs)
- Automatic format detection
- Graceful handling of malformed records

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- `curses` library (built-in on Unix/macOS; use `windows-curses` on Windows)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/json-tui-viewer.git
cd json-tui-viewer

# Optional: Install Windows support
pip install windows-curses  # Windows only
```

### Basic Usage

```bash
# View a JSON file
python json_viewer.py data.json

# View a JSONL file (one object per line)
python json_viewer.py logs.jsonl

# View large files (millions of records) - works instantly!
python json_viewer.py huge_dataset.jsonl
```

## ⌨️ Keyboard Shortcuts

| Key(s)          | Action                                  |
|-----------------|-----------------------------------------|
| `↑` `↓` `j` `k` | Navigate tree nodes                     |
| `→` `l`         | Expand current node                     |
| `←`             | Collapse current node                   |
| `Enter`         | View full value (leaf nodes)            |
| `a`             | Expand current object                   |
| `z`             | Collapse current object                 |
| `A`             | Expand **all** objects                  |
| `Z`             | Collapse **all** objects                |
| `s`             | Search in current field                 |
| `F`             | Global search (all fields) + auto-filter|
| `f`             | Field filter selector                   |
| `n` / `p`       | Next/previous search result             |
| `g`             | Go to object by index                   |
| `Home` / `End`  | First/last object                       |
| `PgUp` / `PgDn` | Previous/next object (preserve position)|
| `q` / `Esc`     | Quit                                    |

## 🔐 Security Features Deep Dive

This viewer was built with security as a first-class concern. Unlike naive JSON viewers, it protects against:

| Threat                 | Protection Mechanism                                  | Limit                     |
|------------------------|-------------------------------------------------------|---------------------------|
| **Billion Laughs**     | Depth validation + node count limits                  | `MAX_JSON_DEPTH=100`      |
| **Zip Bombs (strings)**| String length validation                              | `MAX_STRING_LENGTH=10MB`  |
| **CVE-2020-10735**     | Number digit count validation                         | `MAX_NUMBER_DIGITS=4300`  |
| **ReDoS Attacks**      | Regex timeout (SIGALRM)                               | `REGEX_TIMEOUT=2s`        |
| **Memory Exhaustion**  | Array/object size limits + expansion caps             | `MAX_ARRAY_ITEMS=1M`      |
| **Device Access**      | Path validation blocking `/dev/`, `/proc/`, `/sys/`   | Hardcoded blocklist       |

> 💡 **Important**: On Python < 3.11, a warning is shown about CVE-2020-10735 vulnerability. Upgrade to Python 3.11+ for built-in protection.

## 📁 Supported File Formats

### Standard JSON
```json
{
  "users": [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"}
  ]
}
```

### JSONL (JSON Lines)
```jsonl
{"timestamp": "2023-01-01T12:00:00Z", "event": "login", "user": "alice"}
{"timestamp": "2023-01-01T12:05:23Z", "event": "purchase", "amount": 49.99}
{"timestamp": "2023-01-01T12:10:45Z", "event": "logout", "user": "alice"}
```

## ⚠️ Limitations & Known Issues

- **Windows Support**: Limited due to lack of `SIGALRM` (regex timeout disabled). Use WSL for full security features.
- **Unicode Rendering**: Complex Unicode may render poorly in some terminals.
- **Very Deep Nesting**: Objects deeper than 100 levels are rejected for security (configurable in source).
- **Huge Strings**: Values >10MB are truncated in viewer (but safely validated).

## 🔧 Configuration (Source Code)

Security limits can be adjusted in `json_viewer.py`:

```python
MAX_JSON_DEPTH = 100                # Max nesting depth
MAX_STRING_LENGTH = 10 * 1024 * 1024  # 10 MB per string
MAX_NUMBER_DIGITS = 4300            # CVE-2020-10735 protection
MAX_ARRAY_ITEMS = 1000000           # Max array size
MAX_OBJECT_KEYS = 100000            # Max object keys
MAX_EXPAND_NODES = 100000           # Max nodes when expanding all
REGEX_TIMEOUT = 2                   # Seconds for regex operations
```

> ⚠️ **Warning**: Relaxing these limits may expose you to DoS attacks. Only adjust if you fully trust your data source.

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgements

- Inspired by [`jq`](https://stedolan.github.io/jq/) and [`fx`](https://github.com/antonmedv/fx)
- Security research from [OWASP JSON Threats](https://owasp.org/www-community/attacks/JSON_Threats)
- CVE-2020-10735 mitigation guidance from Python Security Team

## 💬 Feedback & Contributions

Found a bug? Have a feature request? We welcome:

- Bug reports (with sample data if possible)
- Security vulnerability disclosures (contact maintainer directly)
- Performance improvements
- Documentation enhancements

**Before contributing**:
1. Check existing issues
2. Run security tests with malicious JSON samples
3. Ensure new features don't weaken security guarantees

## Attribution
Parts of this code were generated with assistance 

---

> 🔒 **Remember**: Never open untrusted JSON files with naive viewers. This tool provides *defense-in-depth* but cannot guarantee 100% safety against novel attack vectors. Always validate input sources.
