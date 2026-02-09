#!/usr/bin/env python3

"""DevNet auto-discovery utility for Accumulate SDK
Parses DevNet logs and configuration to extract endpoints and faucet account
"""

import json
import os
import re
import subprocess
import sys
from typing import Dict


def discover_devnet_config(devnet_dir: str) -> Dict[str, str]:
    """Discover DevNet configuration from logs and Docker containers"""
    config = {}

    # Set default values
    config['ACC_DEVNET_DIR'] = devnet_dir
    config['ACC_RPC_URL_V2'] = 'http://localhost:26660/v2'
    config['ACC_RPC_URL_V3'] = 'http://localhost:26660/v3'
    config['ACC_FAUCET_ACCOUNT'] = 'acc://a21555da824d14f3f066214657a44e6a1a347dad3052a23a/ACME'  # fallback

    # Try to get more specific info from Docker logs
    try:
        result = subprocess.run([
            'docker', 'logs', 'devnet-accumulate-instance-accumulate-devnet-1'
        ], cwd=devnet_dir, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            logs = result.stdout

            # Extract listening address
            listening_pattern = r'Listening.*"IP":"([^"]+)".*"Port":(\d+)'
            listening_match = re.search(listening_pattern, logs)
            if listening_match:
                host = listening_match.group(1)
                port = listening_match.group(2)
                config['ACC_RPC_URL_V2'] = f'http://{host}:{port}/v2'
                config['ACC_RPC_URL_V3'] = f'http://{host}:{port}/v3'

            # Extract faucet account
            faucet_pattern = r'Faucet.*account=(acc://[^\s]+)'
            faucet_match = re.search(faucet_pattern, logs)
            if faucet_match:
                config['ACC_FAUCET_ACCOUNT'] = faucet_match.group(1)

    except Exception as e:
        print(f'Warning: Could not parse Docker logs: {e}')

    # Override with environment variables if set
    for key in config.keys():
        env_value = os.environ.get(key)
        if env_value:
            config[key] = env_value

    # Test connectivity
    test_connectivity(config)

    return config


def test_connectivity(config: Dict[str, str]) -> None:
    """Test connectivity to discovered endpoints"""
    # Test V3 endpoint
    try:
        result = subprocess.run([
            'curl', '-s', '-X', 'POST',
            config['ACC_RPC_URL_V3'],
            '-H', 'Content-Type: application/json',
            '-d', '{"jsonrpc":"2.0","method":"network-status","params":{},"id":1}'
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            response = json.loads(result.stdout)
            if 'result' in response:
                network_name = response['result'].get('network', {}).get('networkName', 'Unknown')
                print(f'[OK] V3 endpoint connected to: {network_name}')
            else:
                print('[ERROR] V3 endpoint: Invalid response')
        else:
            print(f'[ERROR] V3 endpoint: HTTP error (exit code {result.returncode})')
    except Exception as e:
        print(f'[ERROR] V3 endpoint test failed: {e}')

    # Test V2 endpoint
    try:
        result = subprocess.run([
            'curl', '-s', '-X', 'POST',
            config['ACC_RPC_URL_V2'],
            '-H', 'Content-Type: application/json',
            '-d', '{"jsonrpc":"2.0","method":"describe","params":{},"id":1}'
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            response = json.loads(result.stdout)
            if 'result' in response:
                version_info = response['result'].get('version', 'Unknown')
                print(f'[OK] V2 endpoint connected, version: {version_info}')
            else:
                print('[ERROR] V2 endpoint: Invalid response')
        else:
            print(f'[ERROR] V2 endpoint: HTTP error (exit code {result.returncode})')
    except Exception as e:
        print(f'[ERROR] V2 endpoint test failed: {e}')


def write_env_local(config: Dict[str, str]) -> None:
    """Write .env.local file to unified/ directory"""
    # Get the unified directory path (parent of tool directory)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    unified_dir = os.path.dirname(script_dir)
    env_local_path = os.path.join(unified_dir, '.env.local')

    try:
        with open(env_local_path, 'w') as f:
            f.write("# Auto-generated DevNet configuration\n")
            f.write(f"# Generated at: {os.popen('date /t & time /t').read().strip()}\n\n")
            for key, value in config.items():
                f.write(f"{key}={value}\n")

        print(f'\n[OK] Wrote configuration to: {env_local_path}')
    except Exception as e:
        print(f'[ERROR] Failed to write .env.local: {e}')


def main():
    """Main entry point"""
    devnet_dir = sys.argv[1] if len(sys.argv) > 1 else r'C:\Accumulate_Stuff\devnet-accumulate-instance'

    print(f'Discovering DevNet configuration from: {devnet_dir}')

    config = discover_devnet_config(devnet_dir)

    print('\n=== DevNet Configuration ===')
    for key, value in config.items():
        print(f'{key}={value}')

    # Write .env.local file
    write_env_local(config)

    print('\n=== Export Commands (Bash) ===')
    for key, value in config.items():
        print(f'export {key}="{value}"')

    print('\n=== Export Commands (PowerShell) ===')
    for key, value in config.items():
        print(f'$env:{key}="{value}"')

    print('\n=== Python Usage ===')
    print('import os')
    for key, value in config.items():
        print(f"os.environ['{key}'] = '{value}'")


if __name__ == '__main__':
    main()