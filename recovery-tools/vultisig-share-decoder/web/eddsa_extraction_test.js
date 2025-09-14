// EdDSA Extraction Test - Find the missing EdDSA extraction method
window.eddsaExtractionTest = {
    
    // Test different WASM session types for EdDSA extraction
    testAlternativeSessionTypes: async function(keyshares, partyIds) {
        console.log("🧪 === TESTING ALTERNATIVE SESSION TYPES FOR EDDSA ===");
        
        const { KeyExportSession, KeygenSession, SignSession, FinalSession } = window.vsWasmModule;
        const results = {};
        
        try {
            // Test 1: KeygenSession approach
            console.log("🔬 Test 1: KeygenSession approach");
            try {
                // Note: KeygenSession might be for key generation, not extraction
                // But let's see what methods it has
                console.log("   KeygenSession static methods:", 
                    Object.getOwnPropertyNames(KeygenSession).filter(name => 
                        typeof KeygenSession[name] === 'function'
                    )
                );
                results.keygenSession = "Available but likely for generation, not extraction";
            } catch (e) {
                console.log(`   KeygenSession test failed: ${e.message}`);
                results.keygenSession = `Error: ${e.message}`;
            }
            
            // Test 2: Check if KeyExportSession has additional static methods
            console.log("🔬 Test 2: KeyExportSession additional methods");
            try {
                const staticMethods = Object.getOwnPropertyNames(KeyExportSession).filter(name => 
                    typeof KeyExportSession[name] === 'function'
                );
                console.log("   KeyExportSession static methods:", staticMethods);
                
                // Check if any methods mention EdDSA, Ed25519, or alternative key types
                const relevantMethods = staticMethods.filter(method => 
                    method.toLowerCase().includes('ed') || 
                    method.toLowerCase().includes('25519') ||
                    method.toLowerCase().includes('key')
                );
                console.log("   Potentially relevant methods:", relevantMethods);
                results.keyExportStaticMethods = staticMethods;
            } catch (e) {
                console.log(`   KeyExportSession method analysis failed: ${e.message}`);
                results.keyExportStaticMethods = `Error: ${e.message}`;
            }
            
            // Test 3: Check instance methods on KeyExportSession
            console.log("🔬 Test 3: KeyExportSession instance methods");
            try {
                const session = KeyExportSession.new(keyshares[0], partyIds);
                const instanceMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(session))
                    .filter(name => typeof session[name] === 'function');
                console.log("   KeyExportSession instance methods:", instanceMethods);
                
                // Check if finish() accepts parameters
                console.log("   Testing if finish() accepts parameters...");
                // Don't actually call with params yet, just log the discovery
                results.keyExportInstanceMethods = instanceMethods;
            } catch (e) {
                console.log(`   KeyExportSession instance analysis failed: ${e.message}`);
                results.keyExportInstanceMethods = `Error: ${e.message}`;
            }
            
            // Test 4: Analyze Keyshare methods for EdDSA
            console.log("🔬 Test 4: Keyshare methods analysis");
            try {
                const keyshare = keyshares[0];
                const keyshareMethodns = Object.getOwnPropertyNames(Object.getPrototypeOf(keyshare))
                    .filter(name => typeof keyshare[name] === 'function');
                console.log("   Keyshare instance methods:", keyshareMethodns);
                
                // Test if there are multiple public key methods
                console.log("   Testing publicKey variations...");
                const publicKeyMethods = keyshareMethodns.filter(method => 
                    method.toLowerCase().includes('public') || 
                    method.toLowerCase().includes('key')
                );
                console.log("   Public key related methods:", publicKeyMethods);
                results.keysharePublicKeyMethods = publicKeyMethods;
            } catch (e) {
                console.log(`   Keyshare method analysis failed: ${e.message}`);
                results.keysharePublicKeyMethods = `Error: ${e.message}`;
            }
            
            // Test 5: Check WASM module for EdDSA-specific classes
            console.log("🔬 Test 5: Searching for EdDSA-specific classes");
            try {
                const wasmModuleProps = Object.getOwnPropertyNames(window.vsWasmModule);
                console.log("   Available WASM classes:", wasmModuleProps);
                
                const eddsaRelated = wasmModuleProps.filter(prop => 
                    prop.toLowerCase().includes('ed') || 
                    prop.toLowerCase().includes('25519') ||
                    prop.toLowerCase().includes('eddsa')
                );
                console.log("   Potentially EdDSA-related classes:", eddsaRelated);
                results.eddsaRelatedClasses = eddsaRelated;
            } catch (e) {
                console.log(`   WASM module analysis failed: ${e.message}`);
                results.eddsaRelatedClasses = `Error: ${e.message}`;
            }
            
        } catch (error) {
            console.log(`❌ Alternative session type test failed: ${error.message}`);
            results.error = error.message;
        }
        
        return results;
    },
    
    // Test if KeyExportSession.finish() accepts parameters
    testFinishMethodParameters: async function(keyshares, partyIds) {
        console.log("🧪 === TESTING FINISH METHOD PARAMETERS ===");
        
        try {
            const { KeyExportSession } = window.vsWasmModule;
            
            // Create session and process keyshares
            const session = KeyExportSession.new(keyshares[0], partyIds);
            const setupMessage = session.setup;
            
            for (let i = 1; i < keyshares.length; i++) {
                const message = KeyExportSession.exportShare(setupMessage, partyIds[i], keyshares[i]);
                session.inputMessage(message.body);
            }
            
            console.log("🔬 Testing finish() method variations:");
            
            // Test 1: Standard finish() (current approach)
            console.log("   Test 1: session.finish() - standard call");
            const result1 = session.finish();
            console.log(`   Result: ${result1.length} bytes`);
            
            // Test 2: Check if finish accepts string parameter for key type
            console.log("   Test 2: Testing if finish() accepts key type parameter");
            try {
                // Create new session for clean test
                const session2 = KeyExportSession.new(keyshares[0], partyIds);
                const setupMessage2 = session2.setup;
                
                for (let i = 1; i < keyshares.length; i++) {
                    const message = KeyExportSession.exportShare(setupMessage2, partyIds[i], keyshares[i]);
                    session2.inputMessage(message.body);
                }
                
                // Try calling finish with different potential parameters
                // Note: These might throw errors, but that's informative
                console.log("      Trying finish('eddsa')...");
                const result2 = session2.finish('eddsa');
                console.log(`      Success! Result: ${result2.length} bytes`);
                return result2;
            } catch (e) {
                console.log(`      finish('eddsa') failed: ${e.message}`);
            }
            
            try {
                const session3 = KeyExportSession.new(keyshares[0], partyIds);
                const setupMessage3 = session3.setup;
                
                for (let i = 1; i < keyshares.length; i++) {
                    const message = KeyExportSession.exportShare(setupMessage3, partyIds[i], keyshares[i]);
                    session3.inputMessage(message.body);
                }
                
                console.log("      Trying finish('ed25519')...");
                const result3 = session3.finish('ed25519');
                console.log(`      Success! Result: ${result3.length} bytes`);
                return result3;
            } catch (e) {
                console.log(`      finish('ed25519') failed: ${e.message}`);
            }
            
            return null;
            
        } catch (error) {
            console.log(`❌ Finish method parameter test failed: ${error.message}`);
            return null;
        }
    },
    
    // Test if there are separate WASM functions for EdDSA
    testSeparateEdDSAExtraction: async function(keyshares, partyIds) {
        console.log("🧪 === TESTING SEPARATE EDDSA EXTRACTION METHODS ===");
        
        try {
            // Check if the raw WASM module has EdDSA-specific functions
            console.log("🔬 Analyzing raw WASM exports");
            
            if (window.vsWasmModule.__wbg_init && window.vsWasmModule.__wbg_init.__wbindgen_wasm_module) {
                const wasmExports = Object.getOwnPropertyNames(window.vsWasmModule.__wbg_init.__wbindgen_wasm_module.exports);
                console.log("   Raw WASM exports count:", wasmExports.length);
                
                const eddsaExports = wasmExports.filter(exp => 
                    exp.toLowerCase().includes('ed') || 
                    exp.toLowerCase().includes('25519') ||
                    exp.toLowerCase().includes('eddsa')
                );
                console.log("   Potential EdDSA exports:", eddsaExports);
                
                return eddsaExports;
            } else {
                console.log("   Cannot access raw WASM exports");
                return null;
            }
            
        } catch (error) {
            console.log(`❌ Separate EdDSA extraction test failed: ${error.message}`);
            return null;
        }
    }
};

console.log("🧪 EdDSA Extraction Test Module loaded - ready to find EdDSA extraction method");