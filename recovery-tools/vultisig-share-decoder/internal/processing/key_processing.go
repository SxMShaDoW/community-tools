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
    "main/internal/crypto"
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

// validateLocalStateExists performs common validation that LocalState is not nil
func validateLocalStateExists(localState map[utils.TssKeyType]crypto.LocalState, secretIndex int) error {
    if localState == nil {
        return fmt.Errorf("localState is nil for secret %d", secretIndex)
    }
    return nil
}

// validateShareIDAndXi performs common validation of ShareID and Xi fields for both key types
func validateShareIDAndXi(keyType utils.TssKeyType, state crypto.LocalState, secretIndex int) error {
    var shareID, xi interface{}
    
    switch keyType {
    case utils.ECDSA:
        shareID = state.ECDSALocalData.ShareID
        xi = state.ECDSALocalData.Xi
    case utils.EdDSA:
        shareID = state.EDDSALocalData.ShareID
        xi = state.EDDSALocalData.Xi
    default:
        return fmt.Errorf("unsupported key type: %v", keyType)
    }
    
    if shareID == nil {
        return fmt.Errorf("ShareID is nil for secret %d", secretIndex)
    }
    if xi == nil {
        return fmt.Errorf("Xi is nil for secret %d", secretIndex)
    }
    
    return nil
}

// buildVSSShares constructs VSS shares from local states with validation for both ECDSA and EdDSA
func buildVSSShares(keyType utils.TssKeyType, threshold int, allSecrets []utils.TempLocalState) (vss.Shares, error) {
    keyTypeName := keyType.String()
    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        // Check if LocalState exists using helper function
        if err := validateLocalStateExists(s.LocalState, i); err != nil {
            return nil, err
        }
        
        // Check if the specific key type exists
        localState, exists := s.LocalState[keyType]
        if !exists {
            return nil, fmt.Errorf("%s key not found in secret %d", keyTypeName, i)
        }

        // Validate ShareID and Xi using helper function
        if err := validateShareIDAndXi(keyType, localState, i); err != nil {
            return nil, err
        }
        
        // Extract ShareID and Xi based on key type with proper type assertion
        var shareID, xi *big.Int
        switch keyType {
        case utils.ECDSA:
            shareID = localState.ECDSALocalData.ShareID
            xi = localState.ECDSALocalData.Xi
        case utils.EdDSA:
            shareID = localState.EDDSALocalData.ShareID
            xi = localState.EDDSALocalData.Xi
        }
        
        share := vss.Share{
            Threshold: threshold,
            ID:        shareID,
            Share:     xi,
        }
        vssShares[i] = &share
    }
    
    log.Printf("Created %d %s vssShares", len(vssShares), keyTypeName)
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

    // Build VSS shares using unified helper function
    vssShares, err := buildVSSShares(utils.ECDSA, threshold, allSecrets)
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
    
    // Build VSS shares using unified helper function
    vssShares, err := buildVSSShares(utils.EdDSA, threshold, allSecrets)
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

    // Process EdDSA coins using the unified handler pattern
    eddsaCoins := GetEnhancedEdDSACoins()
    coinKeys := make([]CoinKeyInfo, 0, len(eddsaCoins))

    for _, coin := range eddsaCoins {
        log.Printf("Processing EdDSA coin: %s", coin.Name)
        
        // Check if the coin has an EdDSA handler
        if coin.EdDSAHandler == nil {
            log.Printf("No EdDSA handler found for coin: %s", coin.Name)
            continue
        }
        
        // Use the EdDSA handler from the coin configuration
        coinInfo, err := coin.EdDSAHandler(privateKeyBytes, publicKeyBytes, coin)
        if err != nil {
            log.Printf("Error processing EdDSA coin %s: %v", coin.Name, err)
            continue
        }

        coinKeys = append(coinKeys, coinInfo)
    }

    return coinKeys, nil
}

