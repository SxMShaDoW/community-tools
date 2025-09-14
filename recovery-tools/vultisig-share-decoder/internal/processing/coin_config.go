package processing

// CoinConfig represents configuration for a supported ECDSA-based cryptocurrency
type CoinConfig struct {
        Name       string
        DerivePath string
}

// CoinConfigEdDSA represents configuration for a supported EdDSA-based cryptocurrency
type CoinConfigEdDSA struct {
        Name       string
        DerivePath string
}

// GetSupportedCoins returns the list of all supported cryptocurrencies with their configurations
func GetSupportedCoins() []CoinConfig {
        return []CoinConfig{
                {
                        Name:       "bitcoin",
                        DerivePath: "m/84'/0'/0'/0/0",
                },
                {
                        Name:       "bitcoinCash",
                        DerivePath: "m/44'/145'/0'/0/0",
                },
                {
                        Name:       "dogecoin",
                        DerivePath: "m/44'/3'/0'/0/0",
                },
                {
                        Name:       "litecoin",
                        DerivePath: "m/84'/2'/0'/0/0",
                },
                {
                        Name:       "thorchain",
                        DerivePath: "m/44'/931'/0'/0/0",
                },
                {
                        Name:       "mayachain",
                        DerivePath: "m/44'/931'/0'/0/0",
                },
                {
                        Name:       "atom",
                        DerivePath: "m/44'/118'/0'/0/0",
                },
                {
                        Name:       "kujira",
                        DerivePath: "m/44'/118'/0'/0/0",
                },
                {
                        Name:       "dydx",
                        DerivePath: "m/44'/118'/0'/0/0",
                },
                {
                        Name:       "terra-classic",
                        DerivePath: "m/44'/118'/0'/0/0",
                },
                {
                        Name:       "terra",
                        DerivePath: "m/44'/118'/0'/0/0",
                },
                {
                        Name:       "ethereum",
                        DerivePath: "m/44'/60'/0'/0/0",
                },
                {
                        Name:       "tron",
                        DerivePath: "m/44'/195'/0'/0/0",
                },
        }
}

// GetEdDSACoins returns coins that use EdDSA
func GetEdDSACoins() []CoinConfigEdDSA {
        return []CoinConfigEdDSA{
                {
                        Name:       "solana",
                        DerivePath: "m/44'/501'/0'/0'",
                },
                {
                        Name:       "sui",
                        DerivePath: "m/44'/784'/0'/0'/0'",
                },
                {
                        Name:       "ton",
                        DerivePath: "m/44'/607'/0'/0'/0'",
                },
        }
}