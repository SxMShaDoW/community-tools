package processing

import (
        "encoding/hex"
        "testing"

        "github.com/btcsuite/btcd/btcutil/hdkeychain"
        "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestDashAndZcashAddressGeneration tests the new Dash and Zcash address generation
// using the exact test data provided by the user
func TestDashAndZcashAddressGeneration(t *testing.T) {
        // Test data provided by the user
        privKeyHex := "1bbfb2b193244ec30a4ec90401808675569c9a8eec76f69dbe9451c3504298fc"
        expectedDashAddress := "XkoQBncrZgAmHSYYhkjZqMF7NhPTBhbWbC"
        expectedZcashAddress := "t1ZiDZcAQMkRPQMEZTkJFAi7oZSJjn73Shb"

        // Convert hex string to private key bytes
        privKeyBytes, err := hex.DecodeString(privKeyHex)
        if err != nil {
                t.Fatalf("failed to decode private key hex: %v", err)
        }

        // Create secp256k1 private key
        privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
        keyPair := &ECKeyPair{
                PrivateKey: privKey,
                PublicKey:  privKey.PubKey(),
        }

        // Create dummy extended key for builder initialization (not used in actual processing)
        extendedKey, err := hdkeychain.NewKeyFromString("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        if err != nil {
                t.Fatalf("failed to create extended key: %v", err)
        }

        // Test Dash
        t.Run("Dash", func(t *testing.T) {
                dashConfig := EnhancedCoinConfig{
                        Name:       "dash",
                        DerivePath: "m/44'/5'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2pkh",
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler: UTXOHandler,
                }

                builder := InitializeCoinBuilder(dashConfig, extendedKey, keyPair)
                builder.SetNetworkParams("mainnet")

                result, err := processDash(builder, keyPair)
                if err != nil {
                        t.Fatalf("processDash failed: %v", err)
                }

                if result.Address != expectedDashAddress {
                        t.Errorf("Dash address mismatch:\nExpected: %s\nGot:      %s", expectedDashAddress, result.Address)
                }

                // Verify other fields are set
                if result.Name != "dash" {
                        t.Errorf("Expected name to be 'dash', got '%s'", result.Name)
                }
                if result.WIFPrivateKey == "" {
                        t.Error("WIF private key should not be empty")
                }
                if result.HexPrivateKey != privKeyHex {
                        t.Errorf("Hex private key mismatch:\nExpected: %s\nGot:      %s", privKeyHex, result.HexPrivateKey)
                }

                t.Logf("✓ Dash test passed - Address: %s", result.Address)
        })

        // Test Zcash
        t.Run("Zcash", func(t *testing.T) {
                zcashConfig := EnhancedCoinConfig{
                        Name:       "zcash",
                        DerivePath: "m/44'/133'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2pkh",
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler: UTXOHandler,
                }

                builder := InitializeCoinBuilder(zcashConfig, extendedKey, keyPair)
                builder.SetNetworkParams("mainnet")

                result, err := processZcash(builder, keyPair)
                if err != nil {
                        t.Fatalf("processZcash failed: %v", err)
                }

                if result.Address != expectedZcashAddress {
                        t.Errorf("Zcash address mismatch:\nExpected: %s\nGot:      %s", expectedZcashAddress, result.Address)
                }

                // Verify other fields are set
                if result.Name != "zcash" {
                        t.Errorf("Expected name to be 'zcash', got '%s'", result.Name)
                }
                if result.WIFPrivateKey == "" {
                        t.Error("WIF private key should not be empty")
                }
                if result.HexPrivateKey != privKeyHex {
                        t.Errorf("Hex private key mismatch:\nExpected: %s\nGot:      %s", privKeyHex, result.HexPrivateKey)
                }

                t.Logf("✓ Zcash test passed - Address: %s", result.Address)
        })
}

// TestDashAndZcashConfigSetup verifies the new coins are properly configured
func TestDashAndZcashConfigSetup(t *testing.T) {
        coins := GetEnhancedECDSACoins()
        
        var dashFound, zcashFound bool
        
        for _, coin := range coins {
                switch coin.Name {
                case "dash":
                        dashFound = true
                        if coin.DerivePath != "m/44'/5'/0'/0/0" {
                                t.Errorf("Wrong derive path for Dash: expected m/44'/5'/0'/0/0, got %s", coin.DerivePath)
                        }
                        if coin.Family != FamilyUTXO {
                                t.Errorf("Wrong family for Dash: expected %s, got %s", FamilyUTXO, coin.Family)
                        }
                        if coin.Handler == nil {
                                t.Error("Handler is nil for Dash")
                        }
                        
                case "zcash":
                        zcashFound = true
                        if coin.DerivePath != "m/44'/133'/0'/0/0" {
                                t.Errorf("Wrong derive path for Zcash: expected m/44'/133'/0'/0/0, got %s", coin.DerivePath)
                        }
                        if coin.Family != FamilyUTXO {
                                t.Errorf("Wrong family for Zcash: expected %s, got %s", FamilyUTXO, coin.Family)
                        }
                        if coin.Handler == nil {
                                t.Error("Handler is nil for Zcash")
                        }
                }
        }
        
        if !dashFound {
                t.Error("Dash configuration not found in GetEnhancedECDSACoins()")
        }
        if !zcashFound {
                t.Error("Zcash configuration not found in GetEnhancedECDSACoins()")
        }
        
        t.Logf("✓ Both Dash and Zcash configurations found and validated")
}

// TestUTXOHandlerWithNewCoins tests the UTXOHandler with the new coins
func TestUTXOHandlerWithNewCoins(t *testing.T) {
        // Create a test extended key
        extendedKey, err := hdkeychain.NewKeyFromString("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        if err != nil {
                t.Fatalf("failed to create extended key: %v", err)
        }

        testCases := []struct {
                name           string
                coinName       string
                derivePath     string
                expectedFamily CoinFamily
        }{
                {
                        name:           "Dash",
                        coinName:       "dash",
                        derivePath:     "m/44'/5'/0'/0/0",
                        expectedFamily: FamilyUTXO,
                },
                {
                        name:           "Zcash",
                        coinName:       "zcash",
                        derivePath:     "m/44'/133'/0'/0/0",
                        expectedFamily: FamilyUTXO,
                },
        }

        for _, tc := range testCases {
                t.Run(tc.name, func(t *testing.T) {
                        config := EnhancedCoinConfig{
                                Name:       tc.coinName,
                                DerivePath: tc.derivePath,
                                Family:     tc.expectedFamily,
                                Params: CoinParams{
                                        "addressType": "p2pkh",
                                        "network":     "mainnet",
                                        "compressed":  true,
                                },
                                Handler: UTXOHandler,
                        }

                        result, err := UTXOHandler(extendedKey, config)
                        if err != nil {
                                t.Fatalf("UTXOHandler failed for %s: %v", tc.coinName, err)
                        }

                        // Verify basic fields are populated
                        if result.Name != tc.coinName {
                                t.Errorf("Expected name to be '%s', got '%s'", tc.coinName, result.Name)
                        }
                        if result.Address == "" {
                                t.Error("Address should not be empty")
                        }
                        if result.WIFPrivateKey == "" {
                                t.Error("WIF private key should not be empty")
                        }
                        if result.HexPrivateKey == "" {
                                t.Error("Hex private key should not be empty")
                        }
                        if result.HexPublicKey == "" {
                                t.Error("Hex public key should not be empty")
                        }

                        t.Logf("✓ %s UTXOHandler test passed - Address: %s", tc.name, result.Address)
                })
        }
}