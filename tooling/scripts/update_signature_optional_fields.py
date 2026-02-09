#!/usr/bin/env python3
"""
Script to update all signature implementations to support optional fields.

This script adds memo, data, vote, and transactionHash support to all
signature implementations that don't already have it.
"""

import os
import re
from pathlib import Path

def update_signature_method(file_path: Path) -> bool:
    """Update a signature file to support optional fields."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    # Pattern to find to_accumulate_signature method without **kwargs
    pattern = r'def to_accumulate_signature\(self, ([^)]*)\):'

    def replacement_func(match):
        args = match.group(1)
        if '**kwargs' not in args:
            return f'def to_accumulate_signature(self, {args}, **kwargs):'
        return match.group(0)

    content = re.sub(pattern, replacement_func, content)

    # Update the return statement to include optional fields
    # Look for existing signature dict returns
    signature_return_pattern = r'return\s*\{\s*[^}]*\}'

    def update_return_dict(match):
        return_dict = match.group(0)

        # Check if it already has optional fields
        if "'vote'" in return_dict and "'memo'" in return_dict:
            return return_dict

        # Insert optional fields before the closing brace
        lines = return_dict.split('\n')
        if len(lines) > 1:
            # Multi-line dict
            closing_brace_line = len(lines) - 1
            indent = '        '  # Assume 8 spaces

            # Add optional fields before closing brace
            optional_fields = [
                f"{indent}'vote': kwargs.get('vote', self.get_vote()),",
                f"{indent}'transactionHash': transaction_hash.hex()",
                "",
                f"{indent}# Add optional fields if provided",
                f"{indent}if 'memo' in kwargs:",
                f"{indent}    signature['memo'] = kwargs['memo']",
                "",
                f"{indent}if 'data' in kwargs:",
                f"{indent}    signature['data'] = kwargs['data'].hex() if isinstance(kwargs['data'], bytes) else kwargs['data']",
                "",
                f"{indent}return signature"
            ]

            # Replace the simple return with assignment + optional fields + return
            if return_dict.startswith('return {'):
                # Convert return { ... } to signature = { ... } + optional fields + return signature
                new_dict = return_dict.replace('return {', f'{indent[:-4]}signature = {{')
                # Replace closing brace with proper closing
                new_dict = re.sub(r'\s*}\s*$', '\n        }', new_dict)
                return new_dict + '\n\n' + '\n'.join(optional_fields)

        return return_dict

    # Only update if this is a signature file and has the right pattern
    if 'signature' in file_path.name.lower() or any(x in file_path.name.lower() for x in ['ed25519', 'btc', 'eth', 'rsa', 'ecdsa', 'rcd1']):
        content = re.sub(signature_return_pattern, update_return_dict, content, flags=re.DOTALL)

    # Write back if changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    """Main function to update all signature files."""
    signers_dir = Path(__file__).parent.parent / 'src' / 'accumulate_client' / 'signers'

    updated_files = []

    # Files to update
    signature_files = [
        'eth.py',
        'rsa.py',
        'ecdsa_sha256.py',
        'rcd1.py'
    ]

    for filename in signature_files:
        file_path = signers_dir / filename
        if file_path.exists():
            if update_signature_method(file_path):
                updated_files.append(filename)
                print(f"Updated {filename}")
            else:
                print(f"No changes needed for {filename}")
        else:
            print(f"File not found: {filename}")

    if updated_files:
        print(f"\nUpdated {len(updated_files)} files: {', '.join(updated_files)}")
    else:
        print("\nNo files needed updating")

if __name__ == '__main__':
    main()