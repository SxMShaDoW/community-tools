package processing

import (
    "encoding/hex"
    "fmt"
    "log"
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




// ProcessECDSAKeysJSON reconstructs ECDSA private key and returns structured data
func ProcessECDSAKeysJSON(threshold int, allSecrets []utils.TempLocalState) (*RootKeyInfo, []CoinKeyInfo, error) {
    log.Printf("Processing ECDSA keys for JSON with threshold: %d, number of secrets: %d", threshold, len(allSecrets))

    // Validate input parameters
    if threshold <= 0 {
        return nil, nil, fmt.Errorf("invalid threshold: %d", threshold)
    }
    if len(allSecrets) == 0 {
        return nil, nil, fmt.Errorf("no secrets provided")
    }
    if threshold > len(allSecrets) {
        return nil, nil, fmt.Errorf("threshold (%d) cannot be greater than number of secrets (%d)", threshold, len(allSecrets))
    }

    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        // Check if LocalState exists
        if s.LocalState == nil {
            return nil, nil, fmt.Errorf("localState is nil for secret %d", i)
        }
        // Check if ECDSA key exists
        localState, exists := s.LocalState[utils.ECDSA]
        if !exists {
            return nil, nil, fmt.Errorf("ECDSA key not found in secret %d", i)
        }

        // Validate ShareID and Xi
        if localState.ECDSALocalData.ShareID == nil {
            return nil, nil, fmt.Errorf("ShareID is nil for secret %d", i)
        }
        if localState.ECDSALocalData.Xi == nil {
            return nil, nil, fmt.Errorf("Xi is nil for secret %d", i)
        }
        share := vss.Share{
            Threshold: threshold,
            ID:        localState.ECDSALocalData.ShareID,
            Share:     localState.ECDSALocalData.Xi,
        }
        vssShares[i] = &share
    }
    log.Printf("Created %d vssShares", len(vssShares))

    curve := binanceTss.S256()
    if curve == nil {
        return nil, nil, fmt.Errorf("failed to get S256 curve")
    }
    
    log.Printf("Attempting to reconstruct with threshold %d from %d shares", threshold, len(vssShares))
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to reconstruct private key: %w", err)
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

    // Process all supported coins using the new JSON handlers
    supportedCoins := GetSupportedCoins()
    coinKeys := make([]CoinKeyInfo, 0, len(supportedCoins))

    for _, coin := range supportedCoins {
        log.Printf("Processing %s key derivation", coin.Name)
        key, err := GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
        if err != nil {
            log.Printf("Error deriving private key for %s: %v", coin.Name, err)
            continue
        }

        // Use the appropriate JSON handler based on coin name
        var coinInfo CoinKeyInfo
        switch coin.Name {
        case "ethereum":
            coinInfo, err = ShowEthereumKeyJSON(key, coin.DerivePath)
        case "bitcoin":
            coinInfo, err = ShowBitcoinKeyJSON(key, coin.DerivePath)
        case "bitcoinCash":
            coinInfo, err = ShowBitcoinCashKeyJSON(key, coin.DerivePath)
        case "dogecoin":
            coinInfo, err = ShowDogecoinKeyJSON(key, coin.DerivePath)
        case "litecoin":
            coinInfo, err = ShowLitecoinKeyJSON(key, coin.DerivePath)
        case "thorchain":
            coinInfo, err = ShowThorchainKeyJSON(key, coin.DerivePath)
        case "mayachain":
            coinInfo, err = ShowMayachainKeyJSON(key, coin.DerivePath)
        case "tron":
            coinInfo, err = ShowTronKeyJSON(key, coin.DerivePath)
        case "atom":
            coinInfo, err = CosmosLikeKeyHandlerJSON(key, "cosmos", "Atom", coin.DerivePath)
        case "kujira":
            coinInfo, err = CosmosLikeKeyHandlerJSON(key, "kujira", "Kujira", coin.DerivePath)
        case "dydx":
            coinInfo, err = CosmosLikeKeyHandlerJSON(key, "dydx", "dYdX", coin.DerivePath)
        case "terra-classic":
            coinInfo, err = CosmosLikeKeyHandlerJSON(key, "terra", "Terra Classic", coin.DerivePath)
        case "terra":
            coinInfo, err = CosmosLikeKeyHandlerJSON(key, "terra", "Terra", coin.DerivePath)
        default:
            log.Printf("Unsupported coin: %s", coin.Name)
            continue
        }
        
        if err != nil {
            log.Printf("Error processing %s key: %v", coin.Name, err)
            continue
        }

        coinKeys = append(coinKeys, coinInfo)
    }

    return rootKeyInfo, coinKeys, nil
}

// ProcessEdDSAKeysJSON reconstructs EdDSA private key and returns structured data
func ProcessEdDSAKeysJSON(threshold int, allSecrets []utils.TempLocalState) ([]CoinKeyInfo, error) {
    log.Printf("Processing EdDSA keys for JSON with threshold: %d, number of secrets: %d", threshold, len(allSecrets))
    
    // Validate input parameters
    if threshold <= 0 {
        return nil, fmt.Errorf("invalid threshold: %d", threshold)
    }
    if len(allSecrets) == 0 {
        return nil, fmt.Errorf("no secrets provided")
    }
    if threshold > len(allSecrets) {
        return nil, fmt.Errorf("threshold (%d) cannot be greater than number of secrets (%d)", threshold, len(allSecrets))
    }
    
    // Check if first secret has EdDSA state
    if _, exists := allSecrets[0].LocalState[utils.EdDSA]; !exists {
        return nil, fmt.Errorf("no EdDSA keys found in secrets")
    }
    
    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        eddsaState, exists := s.LocalState[utils.EdDSA]
        if !exists {
            return nil, fmt.Errorf("EdDSA key not found in secret %d", i)
        }
        
        share := vss.Share{
            Threshold: threshold,
            ID:        eddsaState.EDDSALocalData.ShareID,
            Share:     eddsaState.EDDSALocalData.Xi,
        }
        vssShares[i] = &share
    }

    curve := binanceTss.Edwards()
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return nil, fmt.Errorf("failed to reconstruct EdDSA private key: %w", err)
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

