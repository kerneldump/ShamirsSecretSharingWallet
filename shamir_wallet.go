package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// Wallet configuration for storage
type WalletConfig struct {
	Threshold   int      `json:"threshold"`
	TotalShares int      `json:"total_shares"`
	Salt        string   `json:"salt"`
	Shares      []string `json:"shares"`
}

// Share represents a single (x,y) point in the polynomial
type Share struct {
	X *big.Int
	Y *big.Int
}

// ShamirWallet implements a wallet using Shamir's Secret Sharing scheme
type ShamirWallet struct {
	threshold   int
	totalShares int
	prime       *big.Int
}

// NewShamirWallet creates a new wallet with the given parameters
func NewShamirWallet(threshold, totalShares int, prime *big.Int) (*ShamirWallet, error) {
	if threshold > totalShares {
		return nil, errors.New("threshold cannot be greater than total shares")
	}

	// Verify that prime is indeed a prime number
	if !prime.ProbablyPrime(20) {
		return nil, errors.New("the provided value is not a valid prime number")
	}

	return &ShamirWallet{
		threshold:   threshold,
		totalShares: totalShares,
		prime:       prime,
	}, nil
}

// generatePolynomial creates a random polynomial of degree (threshold-1)
// with the secret as the constant term (coefficient of x^0)
func (w *ShamirWallet) generatePolynomial(secret *big.Int) []*big.Int {
	coefficients := make([]*big.Int, w.threshold)
	coefficients[0] = new(big.Int).Set(secret) // First coefficient is the secret

	// Generate random coefficients for the polynomial
	for i := 1; i < w.threshold; i++ {
		// Generate a random coefficient less than the prime
		coeff, err := rand.Int(rand.Reader, w.prime)
		if err != nil {
			log.Fatalf("Failed to generate random coefficient: %v", err)
		}
		coefficients[i] = coeff
	}
	return coefficients
}

// evaluatePolynomial computes the value of the polynomial at point x
// using Horner's method for efficient evaluation
func (w *ShamirWallet) evaluatePolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	// Start with the highest degree coefficient
	result := new(big.Int).Set(coefficients[len(coefficients)-1])

	// Apply Horner's method
	for i := len(coefficients) - 2; i >= 0; i-- {
		// result = (result * x + coefficient) % prime
		result.Mul(result, x)
		result.Add(result, coefficients[i])
		result.Mod(result, w.prime)
	}
	return result
}

// GenerateKey creates a new private key and splits it into shares
func (w *ShamirWallet) GenerateKey() ([]byte, []Share, error) {
	// Generate a random 256-bit private key
	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Convert private key to big.Int
	secret := new(big.Int).SetBytes(privateKey)

	// Generate polynomial coefficients
	coefficients := w.generatePolynomial(secret)

	// Generate shares (x,y) points
	shares := make([]Share, w.totalShares)
	for x := 1; x <= w.totalShares; x++ {
		bigX := big.NewInt(int64(x))
		y := w.evaluatePolynomial(coefficients, bigX)
		shares[x-1] = Share{
			X: bigX,
			Y: new(big.Int).Set(y),
		}
	}

	log.Println("Private key and shares generated successfully")
	return privateKey, shares, nil
}

// interpolateLagrange reconstructs the secret using Lagrange interpolation
func (w *ShamirWallet) interpolateLagrange(shares []Share) (*big.Int, error) {
	if len(shares) < w.threshold {
		return nil, fmt.Errorf("need at least %d shares to reconstruct the secret", w.threshold)
	}

	// Initialize result to 0
	secret := new(big.Int).SetInt64(0)
	zero := new(big.Int).SetInt64(0)

	// For each share, compute its Lagrange basis polynomial and add its contribution
	for i, share := range shares {
		if len(shares) <= i {
			break
		}

		// Calculate the Lagrange basis polynomial for this share
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		// Compute the basis polynomial without the y value yet
		for j, otherShare := range shares {
			if i == j {
				continue
			}

			// numerator *= -otherShare.X
			negX := new(big.Int).Neg(otherShare.X)
			numerator.Mul(numerator, negX)
			numerator.Mod(numerator, w.prime)

			// denominator *= (share.X - otherShare.X)
			diff := new(big.Int).Sub(share.X, otherShare.X)
			denominator.Mul(denominator, diff)
			denominator.Mod(denominator, w.prime)
		}

		// Calculate the inverse of denominator using Fermat's little theorem
		if denominator.Cmp(zero) == 0 {
			return nil, errors.New("invalid shares provided; cannot compute inverse denominator")
		}

		// In a prime field, the multiplicative inverse of a is a^(p-2) mod p
		// Using Fermat's little theorem
		exponent := new(big.Int).Sub(w.prime, big.NewInt(2))
		denominatorInv := new(big.Int).Exp(denominator, exponent, w.prime)

		// Compute the Lagrange basis value: numerator * denominatorInv
		lagrangeBasis := new(big.Int).Mul(numerator, denominatorInv)
		lagrangeBasis.Mod(lagrangeBasis, w.prime)

		// Multiply by the y-value and add to the result
		term := new(big.Int).Mul(share.Y, lagrangeBasis)
		term.Mod(term, w.prime)
		secret.Add(secret, term)
		secret.Mod(secret, w.prime)
	}

	return secret, nil
}

// ReconstructKey rebuilds the private key from the provided shares
func (w *ShamirWallet) ReconstructKey(shares []Share) ([]byte, error) {
	secret, err := w.interpolateLagrange(shares)
	if err != nil {
		return nil, err
	}

	// Convert the big.Int secret back to a 32-byte private key
	privateKey := secret.Bytes()

	// Ensure the private key is exactly 32 bytes (pad with leading zeros if necessary)
	if len(privateKey) < 32 {
		paddedKey := make([]byte, 32)
		copy(paddedKey[32-len(privateKey):], privateKey)
		privateKey = paddedKey
	}

	return privateKey, nil
}

// deriveKey derives an encryption key from a password using PBKDF2
func deriveKey(password string, salt []byte) []byte {
	// Use PBKDF2 with SHA-256 to derive a 32-byte (256-bit) key
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// encryptShare encrypts a share using AES-GCM
func encryptShare(share Share, key []byte) (string, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create a new GCM cipher mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create a nonce (96 bits as recommended for GCM)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Convert share to a string representation
	shareData := []byte(fmt.Sprintf("%s:%s", share.X.String(), share.Y.String()))

	// Encrypt the share data
	ciphertext := aesGCM.Seal(nil, nonce, shareData, nil)

	// Combine nonce and ciphertext and encode to base64
	encrypted := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// decryptShare decrypts an encrypted share using AES-GCM
func decryptShare(encryptedShare string, key []byte) (Share, error) {
	// Decode the base64 string
	data, err := base64.StdEncoding.DecodeString(encryptedShare)
	if err != nil {
		return Share{}, fmt.Errorf("failed to decode share: %w", err)
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return Share{}, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create a new GCM cipher mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return Share{}, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return Share{}, errors.New("encrypted share is too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the share data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Share{}, fmt.Errorf("failed to decrypt share: %w", err)
	}

	// Split the plaintext into x and y components
	parts := strings.Split(string(plaintext), ":")
	if len(parts) != 2 {
		return Share{}, errors.New("invalid share format")
	}

	// Parse the x and y values
	x := new(big.Int)
	y := new(big.Int)
	if _, ok := x.SetString(parts[0], 10); !ok {
		return Share{}, errors.New("failed to parse X value")
	}
	if _, ok := y.SetString(parts[1], 10); !ok {
		return Share{}, errors.New("failed to parse Y value")
	}

	return Share{X: x, Y: y}, nil
}

// promptPassword securely prompts for a password without echoing to the terminal
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Print a newline after the password input
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// commandGenerate handles the generate command
func commandGenerate(threshold, totalShares int, outputFile string) error {
	// Prompt for encryption password
	password, err := promptPassword("Enter a password to encrypt the shares: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if password == "" {
		return errors.New("password cannot be empty")
	}

	confirmPassword, err := promptPassword("Confirm password: ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation password: %w", err)
	}
	if password != confirmPassword {
		return errors.New("passwords do not match")
	}

	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key
	key := deriveKey(password, salt)

	// secp256k1 prime
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	// Create a wallet
	wallet, err := NewShamirWallet(threshold, totalShares, prime)
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	// Generate private key and shares
	_, shares, err := wallet.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate wallet: %w", err)
	}

	// Encrypt each share
	encryptedShares := make([]string, len(shares))
	for i, share := range shares {
		encryptedShare, err := encryptShare(share, key)
		if err != nil {
			return fmt.Errorf("failed to encrypt share %d: %w", i+1, err)
		}
		encryptedShares[i] = encryptedShare
	}

	// Create wallet configuration for storage
	walletConfig := WalletConfig{
		Threshold:   threshold,
		TotalShares: totalShares,
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Shares:      encryptedShares,
	}

	// Create output file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write wallet configuration as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(walletConfig); err != nil {
		return fmt.Errorf("failed to write wallet configuration: %w", err)
	}

	log.Printf("Wallet generated and saved to %s", outputFile)
	log.Println("IMPORTANT: Distribute the encrypted shares securely and remember the password used for encryption.")

	return nil
}

// commandReconstruct handles the reconstruct command
func commandReconstruct(walletFile string, shareFiles []string) error {
	// Prompt for decryption password
	password, err := promptPassword("Enter the password to decrypt the shares: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if password == "" {
		return errors.New("password cannot be empty")
	}

	// Read wallet configuration
	file, err := os.Open(walletFile)
	if err != nil {
		return fmt.Errorf("failed to open wallet file: %w", err)
	}
	defer file.Close()

	var walletConfig WalletConfig
	if err := json.NewDecoder(file).Decode(&walletConfig); err != nil {
		return fmt.Errorf("failed to read wallet configuration: %w", err)
	}

	// Check required fields
	if walletConfig.Threshold == 0 || walletConfig.TotalShares == 0 || walletConfig.Salt == "" || len(walletConfig.Shares) == 0 {
		return errors.New("wallet file is missing required fields")
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(walletConfig.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	// Derive encryption key
	key := deriveKey(password, salt)

	// secp256k1 prime
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	// Create the wallet
	wallet, err := NewShamirWallet(walletConfig.Threshold, walletConfig.TotalShares, prime)
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	// Read and decrypt the provided shares
	var shares []Share
	for _, shareFile := range shareFiles {
		// Check if the input is a share index or a file path
		shareIndex, err := strconv.Atoi(shareFile)
		var encryptedShare string

		if err == nil && shareIndex > 0 && shareIndex <= len(walletConfig.Shares) {
			// Input is a share index
			encryptedShare = walletConfig.Shares[shareIndex-1]
		} else {
			// Try to read it as a file
			shareBytes, err := os.ReadFile(shareFile)
			if err != nil {
				return fmt.Errorf("failed to read share file %s: %w", shareFile, err)
			}
			encryptedShare = strings.TrimSpace(string(shareBytes))
		}

		// Decrypt the share
		share, err := decryptShare(encryptedShare, key)
		if err != nil {
			return fmt.Errorf("failed to decrypt share: %w", err)
		}
		shares = append(shares, share)
	}

	// Check if we have enough shares
	if len(shares) < walletConfig.Threshold {
		return fmt.Errorf("at least %d shares are required to reconstruct the private key", walletConfig.Threshold)
	}

	// Reconstruct the private key
	privateKey, err := wallet.ReconstructKey(shares)
	if err != nil {
		return fmt.Errorf("failed to reconstruct private key: %w", err)
	}

	// Display the reconstructed private key
	fmt.Printf("Reconstructed Private Key (Hex): %x\n", privateKey)

	return nil
}

func main() {
	// Create the main command
	generateCmd := flag.NewFlagSet("generate", flag.ExitOnError)
	generateThreshold := generateCmd.Int("t", 0, "Number of shares required to reconstruct the private key")
	generateShares := generateCmd.Int("n", 0, "Total number of shares to generate")
	generateOutput := generateCmd.String("o", "", "Output file to save the wallet data")

	reconstructCmd := flag.NewFlagSet("reconstruct", flag.ExitOnError)
	reconstructWallet := reconstructCmd.String("w", "", "Path to the wallet JSON file")
	reconstructShares := reconstructCmd.String("s", "", "Space-separated list of shares to reconstruct the private key")

	// Parse the command
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  generate -t <threshold> -n <total_shares> -o <output_file>")
		fmt.Println("  reconstruct -w <wallet_file> -s <share1> <share2> ... <shareN>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		generateCmd.Parse(os.Args[2:])
		if *generateThreshold <= 0 || *generateShares <= 0 || *generateOutput == "" {
			generateCmd.PrintDefaults()
			os.Exit(1)
		}
		if err := commandGenerate(*generateThreshold, *generateShares, *generateOutput); err != nil {
			log.Fatalf("Error generating wallet: %v", err)
		}

	case "reconstruct":
		reconstructCmd.Parse(os.Args[2:])
		if *reconstructWallet == "" || *reconstructShares == "" {
			reconstructCmd.PrintDefaults()
			os.Exit(1)
		}

		// Split the shares string by space
		shareFiles := strings.Fields(*reconstructShares)
		if len(shareFiles) == 0 {
			log.Fatal("No shares provided")
		}

		if err := commandReconstruct(*reconstructWallet, shareFiles); err != nil {
			log.Fatalf("Error reconstructing wallet: %v", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Usage:")
		fmt.Println("  generate -t <threshold> -n <total_shares> -o <output_file>")
		fmt.Println("  reconstruct -w <wallet_file> -s <share1> <share2> ... <shareN>")
		os.Exit(1)
	}
}
