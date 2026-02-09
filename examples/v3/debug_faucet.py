#!/usr/bin/env python3
"""Debug script to test faucet and query functionality."""

from accumulate_client import Accumulate
from accumulate_client.crypto.ed25519 import Ed25519KeyPair
import requests
import time

# KERMIT_V2 = 'https://kermit.accumulatenetwork.io/v2'
# KERMIT_V3 = 'https://kermit.accumulatenetwork.io/v3'

# For local DevNet testing, uncomment these:
KERMIT_V2 = "http://127.0.0.1:26660/v2"
KERMIT_V3 = "http://127.0.0.1:26660/v3"


def main():
    # Generate keypair
    lite_kp = Ed25519KeyPair.generate()
    lid = lite_kp.derive_lite_identity_url()
    lta = lite_kp.derive_lite_token_account_url('ACME')

    print(f'Lite Identity: {lid}')
    print(f'Lite Token Account: {lta}')

    # Try faucet with V2
    print('\n--- Testing Faucet (V2) ---')
    response = requests.post(
        KERMIT_V2,
        json={
            'jsonrpc': '2.0',
            'method': 'faucet',
            'params': {'url': lta},
            'id': 1
        },
        timeout=30
    )
    print(f'Response status: {response.status_code}')
    faucet_result = response.json()
    print(f'Response: {faucet_result}')

    # Check for errors in faucet response
    if 'error' in faucet_result:
        print(f"FAUCET ERROR: {faucet_result['error']}")

    print('\nWaiting 10 seconds for transaction to process...')
    time.sleep(20)

    # Try querying the account with V3
    print('\n--- Testing Query (V3) ---')
    base_endpoint = KERMIT_V3.replace('/v3', '')
    client = Accumulate(base_endpoint)
    try:
        result = client.v3.query(lta)
        print(f'V3 Query result: {result}')
        balance = result.get('account', {}).get('balance')
        print(f'Balance from V3: {balance}')
    except Exception as e:
        print(f'V3 Query error: {type(e).__name__}: {e}')

    # Try V2 query
    print('\n--- Testing Query (V2) ---')
    try:
        v2_response = requests.post(
            KERMIT_V2,
            json={
                'jsonrpc': '2.0',
                'method': 'query',
                'params': {'url': lta},
                'id': 2
            },
            timeout=30
        )
        v2_result = v2_response.json()
        print(f'V2 Query response: {v2_result}')
        if 'result' in v2_result:
            v2_balance = v2_result.get('result', {}).get('data', {}).get('balance')
            print(f'Balance from V2: {v2_balance}')
        if 'error' in v2_result:
            print(f"V2 QUERY ERROR: {v2_result['error']}")
    except Exception as e:
        print(f'V2 Query error: {type(e).__name__}: {e}')

    client.close()

    print('\n--- Summary ---')
    print('If the faucet returned a txid but balance is 0 or error,')
    print('it may take more time for the transaction to settle.')
    print('The Kermit testnet may also be slow or congested.')

if __name__ == '__main__':
    main()
