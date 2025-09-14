package processing

import (
        "encoding/hex"
        "fmt"
        "crypto/ed25519"

        "github.com/btcsuite/btcd/btcutil"
        "github.com/btcsuite/btcd/btcutil/hdkeychain"
        "github.com/btcsuite/btcd/chaincfg"
        coskey "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
        "github.com/cosmos/cosmos-sdk/types"
        sdk "github.com/cosmos/cosmos-sdk/types"
        ethcrypto "github.com/ethereum/go-ethereum/crypto"
        "github.com/gcash/bchd/bchec"
        bchChainCfg "github.com/gcash/bchd/chaincfg"
        "github.com/gcash/bchutil"
        dogec "github.com/eager7/dogd/btcec"
        dogechaincfg "github.com/eager7/dogd/chaincfg"
        "github.com/eager7/dogutil"
        "github.com/ltcsuite/ltcd/ltcutil"
        ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
        "main/internal/crypto"
        "github.com/btcsuite/btcutil/base58"
        "golang.org/x/crypto/blake2b"
        "golang.org/x/crypto/sha3"
        "crypto/sha256"
        "github.com/tonkeeper/tongo/wallet"
)

func GetDerivedPrivateKeys(derivePath string, rootPrivateKey *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
        pathBuf, err := crypto.GetDerivePathBytes(derivePath)
        if err != nil {
                return nil, fmt.Errorf("get derive path bytes failed: %w", err)
        }
        key := rootPrivateKey
        for _, item := range pathBuf {
                key, err = key.Derive(item)
                if err != nil {
                        return nil, err
                }
        }
        return key, nil
}














// ShowEthereumKeyJSON returns structured Ethereum key information
func ShowEthereumKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("ethereum", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(ethcrypto.PubkeyToAddress(*nonHardenedPubKey.ToECDSA()).Hex())
        
        return builder.Build(), nil
}

// ShowBitcoinKeyJSON returns structured Bitcoin key information
func ShowBitcoinKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("bitcoin", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        net := &chaincfg.MainNetParams
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }
        
        wif, err := btcutil.NewWIF(nonHardenedPrivKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        builder.SetNetworkParams("mainnet")
        builder.SetAdditionalInfo("p2wpkh")
        
        return builder.Build(), nil
}

// ShowBitcoinCashKeyJSON returns structured Bitcoin Cash key information
func ShowBitcoinCashKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("bitcoinCash", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        net := &bchChainCfg.MainNetParams
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }
        
        bchNonHardenedPrivKey, _ := bchec.PrivKeyFromBytes(bchec.S256(), nonHardenedPrivKey.Serialize())
        wif, err := bchutil.NewWIF(bchNonHardenedPrivKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}

// ShowDogecoinKeyJSON returns structured Dogecoin key information
func ShowDogecoinKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("dogecoin", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        net := &dogechaincfg.MainNetParams
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }
        
        dogutilNonHardenedPrivKey, _ := dogec.PrivKeyFromBytes(dogec.S256(), nonHardenedPrivKey.Serialize())
        wif, err := dogutil.NewWIF(dogutilNonHardenedPrivKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := dogutil.NewAddressPubKeyHash(dogutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}

// ShowLitecoinKeyJSON returns structured Litecoin key information
func ShowLitecoinKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("litecoin", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        net := &ltcchaincfg.MainNetParams
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }
        
        wif, err := ltcutil.NewWIF(nonHardenedPrivKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := ltcutil.NewAddressWitnessPubKeyHash(ltcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}

// CosmosLikeKeyHandlerJSON returns structured Cosmos-like chain key information
func CosmosLikeKeyHandlerJSON(extendedPrivateKey *hdkeychain.ExtendedKey, bech32PrefixAcc string, coinName, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder(coinName, derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())

        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        compressedPubkey := coskey.PubKey{
                Key: nonHardenedPubKey.SerializeCompressed(),
        }

        // Generate the address bytes
        addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())

        // Use sdk.Bech32ifyAccPub with the correct prefix
        bech32Addr := sdk.MustBech32ifyAddressBytes(bech32PrefixAcc, addrBytes)
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(bech32Addr)
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}

// ShowThorchainKeyJSON returns structured THORChain key information
func ShowThorchainKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("THORChain", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        config := sdk.GetConfig()
        config.SetBech32PrefixForAccount("thor", "thorpub")
        config.SetBech32PrefixForValidator("thorv", "thorvpub")
        config.SetBech32PrefixForConsensusNode("thorc", "thorcpub")

        compressedPubkey := coskey.PubKey{
                Key: nonHardenedPubKey.SerializeCompressed(),
        }
        addr := types.AccAddress(compressedPubkey.Address().Bytes())
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(addr.String())
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}

// ShowMayachainKeyJSON returns structured MAYAChain key information
func ShowMayachainKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("MAYAChain", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        config := sdk.GetConfig()
        config.SetBech32PrefixForAccount("maya", "mayapub")
        config.SetBech32PrefixForValidator("mayav", "mayavpub")
        config.SetBech32PrefixForConsensusNode("mayac", "mayacpub")

        compressedPubkey := coskey.PubKey{
                Key: nonHardenedPubKey.SerializeCompressed(),
        }
        addr := types.AccAddress(compressedPubkey.Address().Bytes())
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(addr.String())
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}

// ShowSolanaKeyFromEdDSAJSON returns structured Solana key information from raw Ed25519 keys
func ShowSolanaKeyFromEdDSAJSON(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("solana", derivePath)
        
        // For Solana, the Ed25519 public key IS the address
        solanaAddress := base58.Encode(eddsaPublicKeyBytes)
        
        builder.SetHexPrivateKey(hex.EncodeToString(eddsaPrivateKeyBytes))
        builder.SetHexPublicKey(hex.EncodeToString(eddsaPublicKeyBytes))
        builder.SetAddress(solanaAddress)
        builder.SetAdditionalInfo("Note: This is a private key scalar and can only be used for signing, not importing into another wallet")
        
        return builder.Build(), nil
}

// ShowSuiKeyFromEdDSAJSON returns structured Sui key information from raw Ed25519 keys
func ShowSuiKeyFromEdDSAJSON(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("sui", derivePath)
        
        // For Sui, we need to create an address from the public key using Blake2b hashing
        // Sui address = Blake2b(scheme_flag || public_key)[0:20]
        // where scheme_flag = 0x00 for Ed25519
        
        // Create the input for hashing: scheme flag (0x00 for Ed25519) + public key
        input := make([]byte, 1+len(eddsaPublicKeyBytes))
        input[0] = 0x00 // Ed25519 scheme flag
        copy(input[1:], eddsaPublicKeyBytes)
        
        // Hash using Blake2b
        hash := blake2b.Sum256(input)
        
        // Use full hash for address
        addressBytes := hash[:]
        
        // Convert to hex with 0x prefix for Sui address format
        suiAddress := "0x" + hex.EncodeToString(addressBytes)
        
        builder.SetHexPrivateKey(hex.EncodeToString(eddsaPrivateKeyBytes))
        builder.SetHexPublicKey(hex.EncodeToString(eddsaPublicKeyBytes))
        builder.SetAddress(suiAddress)
        builder.SetAdditionalInfo("Note: This is a private key scalar and can only be used for signing, not importing into another wallet")
        
        return builder.Build(), nil
}

// ShowTronKeyJSON returns structured Tron key information
func ShowTronKeyJSON(extendedPrivateKey *hdkeychain.ExtendedKey, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("tron", derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())
        
        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        // Get uncompressed public key (64 bytes + 0x04 prefix)
        pubKeyECDSA := nonHardenedPubKey.ToECDSA()
        pubKeyBytes := ethcrypto.FromECDSAPub(pubKeyECDSA)
        
        // Remove the 0x04 prefix to get the 64-byte uncompressed key
        pubKeyNoPrefix := pubKeyBytes[1:]
        
        // Hash with Keccak256
        hash := sha3.NewLegacyKeccak256()
        hash.Write(pubKeyNoPrefix)
        pubKeyHash := hash.Sum(nil)
        
        // Take the last 20 bytes
        ethAddr := pubKeyHash[12:]
        
        // Prefix with Tron version byte (0x41 for mainnet)
        tronAddr := make([]byte, 21)
        tronAddr[0] = 0x41
        copy(tronAddr[1:], ethAddr)
        
        // Calculate checksum using double SHA256
        firstSHA := sha256.Sum256(tronAddr)
        secondSHA := sha256.Sum256(firstSHA[:])
        checksum := secondSHA[:4]
        
        // Combine address + checksum and encode with Base58
        addrWithChecksum := make([]byte, 25)
        copy(addrWithChecksum[:21], tronAddr)
        copy(addrWithChecksum[21:], checksum)
        
        tronAddress := base58.Encode(addrWithChecksum)
        
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetHexPublicKey(hex.EncodeToString(pubKeyBytes))
        builder.SetAddress(tronAddress)
        
        return builder.Build(), nil
}

// ShowTonKeyFromEdDSAJSON returns structured TON key information from raw Ed25519 keys
func ShowTonKeyFromEdDSAJSON(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("ton", derivePath)
        
        // Validate key lengths
        if len(eddsaPrivateKeyBytes) != 32 {
                return builder.Build(), fmt.Errorf("private key must be 32 bytes, got %d", len(eddsaPrivateKeyBytes))
        }
        if len(eddsaPublicKeyBytes) != 32 {
                return builder.Build(), fmt.Errorf("public key must be 32 bytes, got %d", len(eddsaPublicKeyBytes))
        }

        // Set wallet parameters for mainnet V3R2 wallet
        ver := wallet.V4R2
        workchain := 0                         // Mainnet workchain
        networkGlobalID := int32(-239)         // Mainnet global ID
        subWalletId := uint32(698983191)       // Default subWalletId for v3R2

        // Generate address using the improved offline method
        addr, err := wallet.GenerateWalletAddress(
                ed25519.PublicKey(eddsaPublicKeyBytes),
                ver,
                &networkGlobalID,
                workchain,
                &subWalletId,
        )
        if err != nil {
                return builder.Build(), fmt.Errorf("error generating wallet address: %w", err)
        }

        // Convert to user-friendly, non-bounceable, mainnet format
        tonAddress := addr.ToHuman(false, false) // bounceable=false, testnet=false
        
        builder.SetHexPrivateKey(hex.EncodeToString(eddsaPrivateKeyBytes))
        builder.SetHexPublicKey(hex.EncodeToString(eddsaPublicKeyBytes))
        builder.SetAddress(tonAddress)
        builder.SetAdditionalInfo("Note: This is a private key scalar and can only be used for signing, not importing into another wallet")
        
        return builder.Build(), nil
}

