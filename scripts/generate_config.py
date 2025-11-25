#!/usr/bin/env python3
"""
Config Generator for Jester Jr File-Based API Validator

This script reads API keys from master_keys.txt and generates TOML configuration
for use with the file-based WASM validator.

Usage:
    python3 scripts/generate_config.py > config-with-keys.toml
    
    # Or to generate just the validator config section:
    python3 scripts/generate_config.py --validator-only
"""

import sys
import json
import argparse
from pathlib import Path

def load_api_keys(file_path: str) -> list:
    """Load API keys from master_keys.txt file."""
    keys = []
    
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                    
                # Basic validation
                if len(line) < 8:
                    print(f"Warning: Line {line_num} has a very short key: {line[:4]}***", file=sys.stderr)
                    
                keys.append(line)
                
    except FileNotFoundError:
        print(f"Error: Could not find {file_path}", file=sys.stderr)
        print("Make sure master_keys.txt exists in the validators/ directory", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        sys.exit(1)
        
    return keys

def generate_validator_config(keys: list) -> str:
    """Generate the validator configuration section."""
    config = {
        "valid_keys": keys,
        "header_name": "x-api-key",
        "case_sensitive": True
    }
    
    # Convert to JSON string for TOML config value
    config_json = json.dumps(config, indent=2)
    
    return f"""# File-based API key validator configuration
[validators.file_api_key]
type = "wasm"
path = "./validators/simple_api_validator.wasm"
timeout_seconds = 5
config = {config_json}"""

def generate_full_config(keys: list) -> str:
    """Generate a complete example configuration."""
    validator_config = generate_validator_config(keys)
    
    return f"""# Jester Jr Configuration with File-Based API Key Validation
# Generated from master_keys.txt with {len(keys)} keys

[global]
log_level = "info"
timeout_seconds = 30

# ═══════════════════════════════════════════════════════════
# VALIDATOR REGISTRY
# ═══════════════════════════════════════════════════════════

{validator_config}

# ═══════════════════════════════════════════════════════════
# LISTENERS WITH VALIDATORS  
# ═══════════════════════════════════════════════════════════

[listener."api"]
ip = "0.0.0.0"
port = 8080
default_action = "reject"

# Protected API route requiring valid API key from master_keys.txt
[[listener."api".routes]]
name = "protected-api"
path_prefix = "/api/protected"
backend = "127.0.0.1:9091"
strip_prefix = true

[[listener."api".routes.validators]]
validator = "file_api_key"
on_failure = "deny"

# Public API route (no validation required)
[[listener."api".routes]]
name = "public-api"
path_prefix = "/api/public"
backend = "127.0.0.1:9090"
strip_prefix = true

# Health check (no validation)
[[listener."api".routes]]
name = "health"
path_prefix = "/health"
backend = "127.0.0.1:9090"
strip_prefix = false"""

def main():
    parser = argparse.ArgumentParser(description="Generate TOML config from master_keys.txt")
    parser.add_argument("--validator-only", action="store_true", 
                       help="Generate only the validator configuration section")
    parser.add_argument("--keys-file", default="validators/master_keys.txt",
                       help="Path to master keys file (default: validators/master_keys.txt)")
    
    args = parser.parse_args()
    
    # Load API keys
    keys = load_api_keys(args.keys_file)
    
    if not keys:
        print("Error: No valid API keys found in master_keys.txt", file=sys.stderr)
        sys.exit(1)
        
    print(f"# Loaded {len(keys)} API keys from {args.keys_file}", file=sys.stderr)
    
    # Generate configuration
    if args.validator_only:
        config = generate_validator_config(keys)
    else:
        config = generate_full_config(keys)
        
    print(config)

if __name__ == "__main__":
    main()