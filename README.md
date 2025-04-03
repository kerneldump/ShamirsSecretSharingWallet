# Shamir's Secret Sharing Wallet

A secure Go implementation of a cryptographic wallet using Shamir's Secret Sharing scheme for distributed key management.

Shamir's secret sharing (SSS) is an efficient secret sharing algorithm for distributing private information (the "secret") among a group. The secret cannot be revealed unless a minimum number of the group's members act together to pool their knowledge. To achieve this, the secret is mathematically divided into parts (the "shares") from which the secret can be reassembled only when a sufficient number of shares are combined. SSS has the property of information-theoretic security, meaning that even if an attacker steals some shares, it is impossible for the attacker to reconstruct the secret unless they have stolen a sufficient number of shares.

## Overview

Shamir Wallet is a command-line tool that allows you to create and manage cryptographic keys with enhanced security through secret sharing. Instead of storing a single private key that represents a single point of failure, this tool splits your key into multiple shares, requiring a threshold number of these shares to reconstruct the original key.

This implementation is based on Shamir's Secret Sharing scheme, a cryptographic algorithm that divides a secret into parts, giving each participant their own unique part. To reconstruct the original secret, a minimum number of parts (threshold) is required.

## Features

- **Threshold Cryptography**: Split a cryptographic key into `n` shares where any `t` shares can reconstruct the original key (`t ≤ n`).
- **Password Protection**: Each share is individually encrypted with AES-GCM using a key derived from your password.
- **Secure Key Generation**: Uses cryptographically secure random number generation for key and polynomial creation.
- **Compatible with secp256k1**: Uses the same prime field as Bitcoin and Ethereum.
- **Flexible Reconstruction**: Reconstruct your key by providing any `t` number of shares.

## Installation

### Prerequisites

- Go 1.16 or later
- The following Go packages:
  - `golang.org/x/crypto/pbkdf2`
  - `golang.org/x/term`

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/shamir-wallet.git
cd shamir-wallet

# Build the binary
go build -o shamir-wallet

# Alternatively, install it to your GOPATH
go install
```

## Usage

### Generating a New Wallet

To create a new wallet and split it into shares:

```bash
./shamir-wallet generate -t <threshold> -n <total_shares> -o <output_file>
```

Where:
- `threshold` is the minimum number of shares required to reconstruct the key
- `total_shares` is the total number of shares to generate
- `output_file` is the path where the wallet configuration will be saved

Example:
```bash
./shamir-wallet generate -t 3 -n 5 -o my-wallet.json
```

This will:
1. Prompt you for a password to encrypt the shares
2. Generate a random 256-bit private key
3. Split the key into 5 shares where any 3 can reconstruct the original
4. Encrypt each share with your password
5. Save the wallet configuration to `my-wallet.json`

### Reconstructing a Wallet

To reconstruct the private key from the shares:

```bash
./shamir-wallet reconstruct -w <wallet_file> -s "<share_indices_or_files>"
```

Where:
- `wallet_file` is the path to the previously created wallet JSON file
- `share_indices_or_files` is a space-separated list of share indices or file paths

Example using share indices:
```bash
./shamir-wallet reconstruct -w my-wallet.json -s "1 3 5"
```

Example using share files:
```bash
./shamir-wallet reconstruct -w my-wallet.json -s "share1.txt share3.txt share5.txt"
```

This will:
1. Prompt you for the password used to encrypt the shares
2. Decrypt the specified shares
3. Reconstruct and display the original private key

## Security Considerations

- The security of your key is only as strong as your password. Use a strong, unique password.
- Store shares securely and separately. If an attacker obtains the threshold number of shares and your password, they can reconstruct your key.
- This implementation uses the secp256k1 elliptic curve's field prime, making it suitable for Bitcoin and Ethereum key management.
- The share encryption uses PBKDF2 with 100,000 iterations for key derivation and AES-GCM for authenticated encryption.

## How It Works

1. **Key Generation**:
   - A random 256-bit private key is generated
   - A random polynomial of degree (threshold-1) is created with the private key as the constant term
   - Each share is a point (x,y) on this polynomial

2. **Key Reconstruction**:
   - Using any `threshold` number of shares, Lagrange interpolation reconstructs the original polynomial
   - The constant term of the polynomial (y-intercept) is the original private key

3. **Share Encryption**:
   - Each share is encrypted with AES-GCM
   - The encryption key is derived from your password using PBKDF2
   - A unique salt is generated and stored in the wallet file

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and informational purposes only. Use at your own risk. Always back up your cryptographic keys using multiple methods.
