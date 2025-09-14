package processing

import (
    "crypto/elliptic"
    "encoding/hex"
    "fmt"
    "log"
    "math/big"
    // "encoding/json"
    "github.com/bnb-chain/tss-lib/v2/crypto/vss"
    binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
    "github.com/btcsuite/btcd/btcutil/hdkeychain"
    // "github.com/btcsuite/btcutil/base58"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "main/internal/utils"
    edwards "github.com/decred/dcrd/dcrec/edwards/v2"

)


// Helper Functions for Common Validation and Share Construction

// validateThresholdAndSecrets performs common validation of threshold and secrets parameters
func validateThresholdAndSecrets(threshold int, allSecrets []utils.TempLocalState) error {
    if threshold <= 0 {
        return fmt.Errorf("invalid threshold: %d", threshold)
    }
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }
    if threshold > len(allSecrets) {
        return fmt.Errorf("threshold (%d) cannot be greater than number of secrets (%d)", threshold, len(allSecrets))
    }
    return nil
}

// buildECDSAVSSShares constructs VSS shares from ECDSA local states with validation
func buildECDSAVSSShares(threshold int, allSecrets []utils.TempLocalState) (vss.Shares, error) {
    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        // Check if LocalState exists
        if s.LocalState == nil {
            return nil, fmt.Errorf("localState is nil for secret %d", i)
        }
        // Check if ECDSA key exists
        localState, exists := s.LocalState[utils.ECDSA]
        if !exists {
            return nil, fmt.Errorf("ECDSA key not found in secret %d", i)
        }

        // Validate ShareID and Xi
        if localState.ECDSALocalData.ShareID == nil {
            return nil, fmt.Errorf("ShareID is nil for secret %d", i)
        }
        if localState.ECDSALocalData.Xi == nil {
            return nil, fmt.Errorf("Xi is nil for secret %d", i)
        }
        
        share := vss.Share{
            Threshold: threshold,
            ID:        localState.ECDSALocalData.ShareID,
            Share:     localState.ECDSALocalData.Xi,
        }
        vssShares[i] = &share
    }
    
    log.Printf("Created %d ECDSA vssShares", len(vssShares))
    return vssShares, nil
}

// buildEdDSAVSSShares constructs VSS shares from EdDSA local states with validation
func buildEdDSAVSSShares(threshold int, allSecrets []utils.TempLocalState) (vss.Shares, error) {
    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        // Check if LocalState exists
        if s.LocalState == nil {
            return nil, fmt.Errorf("localState is nil for secret %d", i)
        }
        // Check if EdDSA key exists
        eddsaState, exists := s.LocalState[utils.EdDSA]
        if !exists {
            return nil, fmt.Errorf("EdDSA key not found in secret %d", i)
        }

        // Validate ShareID and Xi
        if eddsaState.EDDSALocalData.ShareID == nil {
            return nil, fmt.Errorf("ShareID is nil for secret %d", i)
        }
        if eddsaState.EDDSALocalData.Xi == nil {
            return nil, fmt.Errorf("Xi is nil for secret %d", i)
        }
        
        share := vss.Share{
            Threshold: threshold,
            ID:        eddsaState.EDDSALocalData.ShareID,
            Share:     eddsaState.EDDSALocalData.Xi,
        }
        vssShares[i] = &share
    }
    
    log.Printf("Created %d EdDSA vssShares", len(vssShares))
    return vssShares, nil
}

// CurveType represents the type of cryptographic curve to use for TSS key reconstruction
type CurveType int

const (
    CurveTypeECDSA CurveType = iota
    CurveTypeEdDSA
)

// reconstructTSSKey performs TSS key reconstruction using the appropriate curve
func reconstructTSSKey(vssShares vss.Shares, threshold int, curveType CurveType) (*big.Int, error) {
    var curve elliptic.Curve
    var curveTypeName string
    
    switch curveType {
    case CurveTypeECDSA:
        curve = binanceTss.S256()
        curveTypeName = "ECDSA"
    case CurveTypeEdDSA:
        curve = binanceTss.Edwards()
        curveTypeName = "EdDSA"
    default:
        return nil, fmt.Errorf("unsupported curve type: %d", curveType)
    }
    
    if curve == nil {
        return nil, fmt.Errorf("failed to get %s curve", curveTypeName)
    }
    
    log.Printf("Attempting to reconstruct %s key with threshold %d from %d shares", curveTypeName, threshold, len(vssShares))
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return nil, fmt.Errorf("failed to reconstruct %s private key: %w", curveTypeName, err)
    }
    
    return tssPrivateKey, nil
}


// ProcessECDSAKeysJSON reconstructs ECDSA private key and returns structured data
func ProcessECDSAKeysJSON(threshold int, allSecrets []utils.TempLocalState) (*RootKeyInfo, []CoinKeyInfo, error) {
    log.Printf("Processing ECDSA keys for JSON with threshold: %d, number of secrets: %d", threshold, len(allSecrets))

    // Validate input parameters using helper function
    if err := validateThresholdAndSecrets(threshold, allSecrets); err != nil {
        return nil, nil, err
    }

    // Build VSS shares using helper function
    vssShares, err := buildECDSAVSSShares(threshold, allSecrets)
    if err != nil {
        return nil, nil, err
    }

    // Reconstruct TSS private key using helper function
    tssPrivateKey, err := reconstructTSSKey(vssShares, threshold, CurveTypeECDSA)
    if err != nil {
        return nil, nil, err
    }
    
    privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
    publicKey := privateKey.PubKey()

    hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
    hexPrivKey := hex.EncodeToString(privateKey.Serialize())

    // Get chaincode
    chaincode := allSecrets[0].LocalState[utils.ECDSA].ChainCodeHex
    chaincodeBuf, err := hex.DecodeString(chaincode)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to decode chaincode: %w", err)
    }
    
    // Create extended private key
    net := &chaincfg.MainNetParams
    extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)

    // Create root key info
    rootKeyInfo := &RootKeyInfo{
        HexPubKeyECDSA:      hexPubKey,
        HexPrivKeyECDSA:     hexPrivKey,
        ChainCode:          chaincode,
        ExtendedPrivKey: extendedPrivateKey.String(),
    }

    // Initialize the coin handler registry
    InitializeCoinHandlerRegistry()
    
    // Process all supported coins using the registry pattern
    enhancedCoins := GetEnhancedECDSACoins()
    coinKeys := make([]CoinKeyInfo, 0, len(enhancedCoins))

    for _, coinConfig := range enhancedCoins {
        log.Printf("Processing %s key derivation", coinConfig.Name)
        key, err := GetDerivedPrivateKeys(coinConfig.DerivePath, extendedPrivateKey)
        if err != nil {
            log.Printf("Error deriving private key for %s: %v", coinConfig.Name, err)
            continue
        }

        // Get handler from registry
        handler, exists := GetCoinHandler(coinConfig.Name)
        if !exists {
            log.Printf("No handler found for coin: %s", coinConfig.Name)
            continue
        }
        
        // Use the handler from the registry
        coinInfo, err := handler(key, coinConfig)
        if err != nil {
            log.Printf("Error processing %s key: %v", coinConfig.Name, err)
            continue
        }

        coinKeys = append(coinKeys, coinInfo)
    }

    return rootKeyInfo, coinKeys, nil
}

// ProcessEdDSAKeysJSON reconstructs EdDSA private key and returns structured data
func ProcessEdDSAKeysJSON(threshold int, allSecrets []utils.TempLocalState) ([]CoinKeyInfo, error) {
    log.Printf("Processing EdDSA keys for JSON with threshold: %d, number of secrets: %d", threshold, len(allSecrets))
    
    // Validate input parameters using helper function
    if err := validateThresholdAndSecrets(threshold, allSecrets); err != nil {
        return nil, err
    }
    
    // Build VSS shares using helper function
    vssShares, err := buildEdDSAVSSShares(threshold, allSecrets)
    if err != nil {
        return nil, err
    }

    // Reconstruct TSS private key using helper function
    tssPrivateKey, err := reconstructTSSKey(vssShares, threshold, CurveTypeEdDSA)
    if err != nil {
        return nil, err
    }
    
    // Generate Ed25519 key pair
    tssPrivateKeyScalar := tssPrivateKey.Bytes()
    privateKey, publicKey, err := edwards.PrivKeyFromScalar(tssPrivateKeyScalar)
    if err != nil {
        return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
    }
    publicKeyBytes := publicKey.Serialize()
    privateKeyBytes := privateKey.Serialize()

    // Process EdDSA coins using the new JSON handlers
    eddsaCoins := GetEdDSACoins()
    coinKeys := make([]CoinKeyInfo, 0, len(eddsaCoins))

    for _, coin := range eddsaCoins {
        log.Printf("Processing EdDSA coin: %s", coin.Name)
        
        // Use the appropriate EdDSA JSON handler based on coin name
        var coinInfo CoinKeyInfo
        switch coin.Name {
        case "solana":
            coinInfo, err = ShowSolanaKeyFromEdDSAJSON(privateKeyBytes, publicKeyBytes, coin.DerivePath)
        case "sui":
            coinInfo, err = ShowSuiKeyFromEdDSAJSON(privateKeyBytes, publicKeyBytes, coin.DerivePath)
        case "ton":
            coinInfo, err = ShowTonKeyFromEdDSAJSON(privateKeyBytes, publicKeyBytes, coin.DerivePath)
        default:
            log.Printf("Unsupported EdDSA coin: %s", coin.Name)
            continue
        }
        
        if err != nil {
            log.Printf("Error processing EdDSA coin %s: %v", coin.Name, err)
            continue
        }

        coinKeys = append(coinKeys, coinInfo)
    }

    return coinKeys, nil
}

