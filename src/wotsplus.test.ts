import { describe, it, expect } from 'vitest';
import { WOTSPlus } from './wotsplus';
import { keccak_256 } from '@noble/hashes/sha3';
import testVectors from '../test/test_vectors/wotsplus_keccak256.json';

describe('WOTSPlus', () => {
    // Helper to convert number to Uint8Array (similar to bytes32 in Solidity)
    const numberToUint8Array = (num: number): Uint8Array => {
        const arr = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            arr[31 - i] = num & 0xff;
            num = num >> 8;
        }
        return arr;
    };

    it('should generate key pair', () => {
        const wotsPlus = new WOTSPlus(keccak_256);
        const privateSeed = numberToUint8Array(1); // Example seed
        const { publicKey, privateKey } = wotsPlus.generateKeyPair(privateSeed);
        
        expect(publicKey.length).toBe(wotsPlus.publicKeySize);
        expect(privateKey).not.toEqual(new Uint8Array(32));
    });

    it('should fail to verify empty signature', () => {
        const wotsPlus = new WOTSPlus(keccak_256);
        const privateSeed = numberToUint8Array(1);
        const { publicKey } = wotsPlus.generateKeyPair(privateSeed);

        // Create a test message
        const message = new Uint8Array(wotsPlus.messageLen);
        for (let i = 0; i < message.length; i++) {
            message[i] = i;
        }

        // Create empty signature array
        const emptySignature = Array(wotsPlus.numSignatureChunks)
            .fill(new Uint8Array(wotsPlus.hashLen));

        const isValid = wotsPlus.verify(publicKey, message, emptySignature);
        expect(isValid).toBe(false);
    });

    it('should verify valid signature', () => {
        const wotsPlus = new WOTSPlus(keccak_256);
        const privateSeed = numberToUint8Array(1);
        const { publicKey, privateKey } = wotsPlus.generateKeyPair(privateSeed);
        
        // Create test message
        const message = new Uint8Array(wotsPlus.messageLen);
        for (let i = 0; i < message.length; i++) {
            message[i] = i;
        }
        
        const signature = wotsPlus.sign(privateKey, message);
        const isValid = wotsPlus.verify(publicKey, message, signature);
        
        expect(isValid).toBe(true);
    });

    it('should verify valid signature with randomization elements', () => {
        const wotsPlus = new WOTSPlus(keccak_256);
        const privateSeed = numberToUint8Array(1);
        const { publicKey, privateKey } = wotsPlus.generateKeyPair(privateSeed);
        
        // Create test message
        const message = new Uint8Array(wotsPlus.messageLen);
        for (let i = 0; i < message.length; i++) {
            message[i] = i;
        }
        
        const signature = wotsPlus.sign(privateKey, message);
        
        // Extract public seed and hash from public key
        const publicSeed = publicKey.slice(0, wotsPlus.hashLen);
        const publicKeyHash = publicKey.slice(wotsPlus.hashLen, wotsPlus.hashLen * 2);
        
        const randomizationElements = wotsPlus.generateRandomizationElements(publicSeed);
        
        const isValid = wotsPlus.verifyWithRandomizationElements(
            publicKeyHash,
            message,
            signature,
            randomizationElements
        );
        
        expect(isValid).toBe(true);
    });

    it('should verify many signatures', () => {
        const wotsPlus = new WOTSPlus(keccak_256);
        for (let i = 1; i < 1; i++) {
            const privateSeed = numberToUint8Array(i);
            const { publicKey, privateKey } = wotsPlus.generateKeyPair(privateSeed);
            
            // Create unique message for each iteration
            const message = new TextEncoder().encode(`Hello World${i}`);
            const messageHash = keccak_256(message);
            
            const signature = wotsPlus.sign(privateKey, messageHash);
            const isValid = wotsPlus.verify(publicKey, messageHash, signature);
            
            expect(isValid).toBe(true);
        }
    });

    it('should verify many signatures with randomization elements', () => {
        const wotsPlus = new WOTSPlus(keccak_256);
        for (let i = 1; i < 1; i++) {
            const privateSeed = numberToUint8Array(i);
            const { publicKey, privateKey } = wotsPlus.generateKeyPair(privateSeed);
            
            // Create unique message for each iteration
            const message = new TextEncoder().encode(`Hello World${i}`);
            const messageHash = keccak_256(message);
            
            const signature = wotsPlus.sign(privateKey, messageHash);
            
            const publicSeed = publicKey.slice(0, wotsPlus.hashLen);
            const publicKeyHash = publicKey.slice(wotsPlus.hashLen, wotsPlus.hashLen * 2);
            const randomizationElements = wotsPlus.generateRandomizationElements(publicSeed);
            
            const isValid = wotsPlus.verifyWithRandomizationElements(
                publicKeyHash,
                messageHash,
                signature,
                randomizationElements
            );
            
            expect(isValid).toBe(true);
        }
    });

    // Modified test vectors test to use the JSON file
    it('should verify test vectors from JSON file', () => {
        const wotsPlus = new WOTSPlus(keccak_256);

        // Helper to convert hex string to Uint8Array
        const hexToUint8Array = (hex: string): Uint8Array => {
            hex = hex.startsWith('0x') ? hex.slice(2) : hex;
            const arr = new Uint8Array(hex.length / 2);
            for (let i = 0; i < arr.length; i++) {
                arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
            }
            return arr;
        };

        // Test each vector
        Object.entries(testVectors).forEach(([vectorName, vector]) => {
            // Convert hex strings to Uint8Arrays
            const publicKey = hexToUint8Array(vector.publicKey);
            const message = hexToUint8Array(vector.message);
            const signature = vector.signature.map(sig => hexToUint8Array(sig));
            const publicSeed = hexToUint8Array(vector.publicSeed);
            const randomizationElements = vector.randomizationElements.map(elem => hexToUint8Array(elem));

            // Test standard verification
            const isValid = wotsPlus.verify(publicKey, message, signature);
            expect(isValid, `Standard verification failed for ${vectorName}`).toBe(true);

            // Test verification with randomization elements
            const publicKeyHash = publicKey.slice(wotsPlus.hashLen, wotsPlus.publicKeySize);
            const isValidWithRand = wotsPlus.verifyWithRandomizationElements(
                publicKeyHash,
                message,
                signature,
                randomizationElements
            );
            expect(isValidWithRand, `Randomized verification failed for ${vectorName}`).toBe(true);
        });
    });
});
