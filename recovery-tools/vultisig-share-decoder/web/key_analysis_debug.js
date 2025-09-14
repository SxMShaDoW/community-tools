// Key Analysis Debug Module for DKLS EdDSA Investigation
// This module adds debug hooks to analyze key extraction behavior

window.keyAnalysisDebug = {
    enabled: true,
    
    // Log detailed analysis of session.finish() result
    analyzeSessionFinishResult: function(privateKeyBytes, sessionInfo = {}) {
        if (!this.enabled) return;
        
        console.log("🔍 === SESSION FINISH ANALYSIS ===");
        console.log(`📏 Private key byte length: ${privateKeyBytes.length}`);
        console.log(`🔢 Private key hex length: ${privateKeyBytes.length * 2} chars`);
        
        // Analyze the byte pattern
        const hexString = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        console.log(`🔑 Private key (first 16 bytes): ${hexString.substring(0, 32)}...`);
        console.log(`🔑 Private key (last 16 bytes): ...${hexString.substring(hexString.length - 32)}`);
        
        // Check for common patterns
        if (privateKeyBytes.length === 32) {
            console.log("📊 ANALYSIS: Standard 32-byte key (likely single ECDSA or EdDSA)");
        } else if (privateKeyBytes.length === 64) {
            console.log("📊 ANALYSIS: 64-byte result - might contain both ECDSA + EdDSA keys!");
            console.log(`   First 32 bytes (potential ECDSA): ${hexString.substring(0, 64)}`);
            console.log(`   Last 32 bytes (potential EdDSA):  ${hexString.substring(64)}`);
        } else {
            console.log(`📊 ANALYSIS: Unexpected length ${privateKeyBytes.length} bytes`);
        }
        
        // Check if all bytes are the same (would indicate an error)
        const uniqueBytes = new Set(privateKeyBytes);
        if (uniqueBytes.size === 1) {
            console.log("⚠️  WARNING: All bytes are identical - likely an error!");
        }
        
        return {
            length: privateKeyBytes.length,
            hexString: hexString,
            analysis: privateKeyBytes.length === 32 ? "single_key" : 
                     privateKeyBytes.length === 64 ? "potential_dual_key" : "unexpected"
        };
    },
    
    // Analyze keyshare public key information
    analyzeKeysharePublicKey: function(keyshare, keyshareIndex = 0) {
        if (!this.enabled) return;
        
        console.log(`🔍 === KEYSHARE ${keyshareIndex} PUBLIC KEY ANALYSIS ===`);
        
        try {
            const publicKeyBytes = keyshare.publicKey();
            const publicKeyHex = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            console.log(`📏 Public key byte length: ${publicKeyBytes.length}`);
            console.log(`🔑 Public key hex: ${publicKeyHex}`);
            
            // Analyze public key format
            if (publicKeyBytes.length === 33) {
                console.log("📊 ANALYSIS: 33-byte compressed ECDSA public key");
            } else if (publicKeyBytes.length === 32) {
                console.log("📊 ANALYSIS: 32-byte EdDSA public key");
            } else if (publicKeyBytes.length === 65) {
                console.log("📊 ANALYSIS: 65-byte uncompressed ECDSA public key");
            } else {
                console.log(`📊 ANALYSIS: Unexpected public key length ${publicKeyBytes.length}`);
            }
            
            return {
                length: publicKeyBytes.length,
                hex: publicKeyHex,
                type: publicKeyBytes.length === 33 ? "ecdsa_compressed" :
                      publicKeyBytes.length === 32 ? "eddsa" :
                      publicKeyBytes.length === 65 ? "ecdsa_uncompressed" : "unknown"
            };
        } catch (error) {
            console.log(`❌ Error analyzing keyshare public key: ${error.message}`);
            return null;
        }
    },
    
    // Compare vault EdDSA public key with keyshare public key
    comparePublicKeys: function(keysharePublicKeyHex, vaultEddsaPublicKey) {
        if (!this.enabled) return;
        
        console.log("🔍 === PUBLIC KEY COMPARISON ===");
        console.log(`🔑 Keyshare public key: ${keysharePublicKeyHex}`);
        console.log(`🔑 Vault EdDSA public key: ${vaultEddsaPublicKey}`);
        
        if (keysharePublicKeyHex === vaultEddsaPublicKey) {
            console.log("✅ MATCH: Keyshare public key matches vault EdDSA public key");
            return "eddsa_match";
        } else {
            console.log("❌ NO MATCH: Keyshare public key differs from vault EdDSA public key");
            console.log("📊 ANALYSIS: Keyshare public key is likely ECDSA, vault has separate EdDSA key");
            return "ecdsa_different";
        }
    },
    
    // Test multiple session approach
    testMultipleSessionApproach: async function(keyshares, partyIds) {
        if (!this.enabled) return;
        
        console.log("🔍 === TESTING MULTIPLE SESSION APPROACH ===");
        
        try {
            const { KeyExportSession } = window.vsWasmModule;
            
            // First session (current approach)
            console.log("🔄 Creating first session...");
            const session1 = KeyExportSession.new(keyshares[0], partyIds);
            
            // Process all keyshares for session 1
            const setupMessage1 = session1.setup;
            for (let i = 1; i < keyshares.length; i++) {
                const message = KeyExportSession.exportShare(setupMessage1, partyIds[i], keyshares[i]);
                session1.inputMessage(message.body);
            }
            
            const result1 = session1.finish();
            const analysis1 = this.analyzeSessionFinishResult(result1, { session: 1 });
            
            // Second session (experimental)
            console.log("🔄 Creating second session with same keyshares...");
            const session2 = KeyExportSession.new(keyshares[0], partyIds);
            
            // Process all keyshares for session 2 (same process)
            const setupMessage2 = session2.setup;
            for (let i = 1; i < keyshares.length; i++) {
                const message = KeyExportSession.exportShare(setupMessage2, partyIds[i], keyshares[i]);
                session2.inputMessage(message.body);
            }
            
            const result2 = session2.finish();
            const analysis2 = this.analyzeSessionFinishResult(result2, { session: 2 });
            
            // Compare results
            console.log("🔍 === COMPARING SESSION RESULTS ===");
            const hex1 = Array.from(result1).map(b => b.toString(16).padStart(2, '0')).join('');
            const hex2 = Array.from(result2).map(b => b.toString(16).padStart(2, '0')).join('');
            
            if (hex1 === hex2) {
                console.log("✅ Sessions return identical results - deterministic");
            } else {
                console.log("❌ Sessions return different results - non-deterministic!");
                console.log("📊 This might indicate session state affects output");
            }
            
            return { analysis1, analysis2, identical: hex1 === hex2 };
            
        } catch (error) {
            console.log(`❌ Error in multiple session test: ${error.message}`);
            return null;
        }
    }
};

// Hook into the existing DKLS processing
console.log("🔧 Key Analysis Debug Module loaded - ready to analyze DKLS key extraction");