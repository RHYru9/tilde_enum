# 🕵️ tilde_enum 🕯️

## 🎯 Overview
A Python tool to exploit the IIS Tilde 8.3 Enumeration Vulnerability, allowing discovery of full file and directory names on vulnerable Microsoft IIS servers.

## ✨ Features
- 🔍 Enumerates hidden file/directory names using tilde vulnerability
- 📋 Supports custom wordlists for scanning
- ⚙️ Configurable scanning options
- 🌐 Proxy support
- 🔮 Optional Google keyword suggestion enhancement

## 🛠️ Requirements
- Python 3
- Wordlist file (recommended: fuzzdb wordlists)

## 🚀 Usage
```bash
python3 enum.py -u <target_url> 
```

### 🔧 Options
- `-h`: Show help message
- `-u`: Target URL to scan
- `-d`: Path to wordlist
- `-e`: Path to extensions file
- `-c`: Cookie header
- `-p`: Proxy configuration
- `-o`: Output file
- `-v`: Verbosity level (0-2)

## 💡 Notes
- Only finds directories with names longer than 8 characters
- Complementary to full directory enumeration tools like DirBuster

## 👥 Credits
- Original Author: Micah Hoffman (@WebBreacher)
- Refactored by: esaBear
- Python 3 Migration: Rhyru9

## 🔗 References
- [IIS Tilde Vulnerability Details](https://soroush.secproject.com/blog/tag/iis-tilde-vulnerability/)
