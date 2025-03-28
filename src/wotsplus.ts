// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// Buffer utility for cross-platform compatibility
const BufferUtil = {
    equals: (a: Uint8Array, b: Uint8Array): boolean => {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    },

    from: (data: Uint8Array): Uint8Array => {
        if (typeof Buffer !== 'undefined') {
            return Buffer.from(data);
        }
        return new Uint8Array(data);
    }
};

// HashFunction interface defines the shape of hash functions that can be used
export interface HashFunction {
    (data: Uint8Array): Uint8Array;
}

export class WOTSPlus {
    private readonly hashFn: HashFunction;

    // HashLen: The WOTS+ `n` security parameter which is the size 
    // of the hash function output in bytes.
    // This is 32 for keccak256 (256 / 8 = 32)
    public readonly hashLen: number;

    // MessageLen: The WOTS+ `m` parameter which is the size 
    // of the message to be signed in bytes 
    // (and also the size of our hash function)
    //
    // This is 32 for keccak256 (256 / 8 = 32)
    //
    // Note that this is not the message length itself as, like 
    // with most signatures, we hash the message and then compute
    // the signature on the hash of the message.
    public readonly messageLen: number;

    // ChainLen: The WOTS+ `w`(internitz) parameter. 
    // This corresponds to the number of hash chains for each public
    // key segment and the base-w representation of the message
    // and checksum.
    // 
    // A larger value means a smaller signature size but a longer
    // computation time.
    // 
    // For XMSS (rfc8391) this value is limited to 4 or 16 because
    // they simplify the algorithm and offer the best trade-offs.
    public readonly chainLen: number;

    // lg(ChainLen) so we don't calculate it repeatedly
    public readonly lgChainLen: number;

    // NumMessageChunks: the `len_1` parameter which is the number of
    // message chunks. This is 
    // ceil(8n / lg(w)) -> ceil(8 * HashLen / lg(ChainLen))
    // or ceil(32*8 / lg(16)) -> 256 / 4 = 64
    // Python:  math.ceil(32*8 / math.log(16,2))
    public readonly numMessageChunks: number;

    // NumChecksumChunks: the `len_2` parameter which is the number of
    // checksum chunks. This is
    // floor(lg(len_1 * (w - 1)) / lg(w)) + 1
    // -> floor(lg(NumMessageChunks * (ChainLen - 1)) / lg(ChainLen)) + 1
    // -> floor(lg(64 * 15) / lg(16)) + 1 = 3
    // Python: math.floor(math.log(64 * 15, 2) / math.log(16, 2)) + 1
    public readonly numChecksumChunks: number;

    public readonly numSignatureChunks: number;

    // SignatureSize: The size of the signature in bytes.
    public readonly signatureSize: number;

    // PublicKeySize: The size of the public key in bytes.
    public readonly publicKeySize: number;

    constructor(
        hashFunction: HashFunction,
        hashLen?: number,
        chainLen: number = 16
    ) {
        this.hashFn = hashFunction;
        
        // Initialize core parameters
        this.hashLen = hashLen ?? 32; // Default to 32 bytes if not specified
        this.messageLen = this.hashLen;
        this.chainLen = chainLen;
        this.lgChainLen = Math.log2(this.chainLen);

        // Compute derived parameters
        this.numMessageChunks = Math.ceil((8 * this.hashLen) / this.lgChainLen);
        
        // Calculate numChecksumChunks
        const checksumBits = Math.floor(
            Math.log2(this.numMessageChunks * (this.chainLen - 1)) / 
            Math.log2(this.chainLen)
        ) + 1;
        this.numChecksumChunks = checksumBits;

        // Calculate remaining parameters
        this.numSignatureChunks = this.numMessageChunks + this.numChecksumChunks;
        this.signatureSize = this.numSignatureChunks * this.hashLen;
        this.publicKeySize = this.hashLen * 2;

        // Validate parameters
        this.validateParameters();
    }

    private validateParameters(): void {
        // Ensure chainLen is a power of 2
        if ((this.chainLen & (this.chainLen - 1)) !== 0) {
            throw new Error("ChainLen must be a power of 2");
        }

        // Ensure hashLen is positive
        if (this.hashLen <= 0) {
            throw new Error("HashLen must be positive");
        }

        // Additional validations as needed
        if (this.chainLen !== 16 && this.chainLen !== 4) {
            throw new Error("ChainLen must be either 4 or 16 for XMSS compatibility");
        }
    }

    // Hash: The WOTS+ `F` hash function.
    private hash(data: Uint8Array): Uint8Array {
        return this.hashFn(data);
    }

    // prf: Generate randomization elements from seed and index
    // Similar to XMSS RFC 8391 section 5.1
    // NOTE: while sha256 and ripemd160 are available in solidity,
    // they are implemented as precompiled contracts and are more expensive for gas. 
    private prf(seed: Uint8Array, index: number): Uint8Array {
        // Create a buffer with prefix (0x03), seed, and index
        const buffer = new Uint8Array(1 + seed.length + 2);
        buffer[0] = 0x03;  // prefix to domain separate
        buffer.set(seed, 1);  // the seed input
        // Set index as 2 bytes (uint16)
        buffer[seed.length + 1] = (index >> 8) & 0xFF;
        buffer[seed.length + 2] = index & 0xFF;
        
        return this.hash(buffer);
    }

    // Generate randomization elements from seed and index
    // Similar to XMSS RFC 8391 section 5.1
    public generateRandomizationElements(publicSeed: Uint8Array): Uint8Array[] {
        const elements: Uint8Array[] = [];
        for (let i = 0; i < this.numSignatureChunks; i++) {
            elements.push(this.prf(publicSeed, i));
        }
        return elements;
    }

    // chain is the c_k^i function, 
    // the hash of (prevChainOut XOR randomization element at index).
    // As a practical matter, we generate the randomization elements
    // via a seed like in XMSS(rfc8391) with a defined PRF.
    private chain(
        prevChainOut: Uint8Array, 
        randomizationElements: Uint8Array[], 
        index: number, 
        steps: number
    ): Uint8Array {
        if (index + steps >= this.chainLen) {
            throw new Error("steps + index must be less than ChainLen");
        }

        let chainOut = prevChainOut;
        for (let i = 1; i <= steps; i++) {
            const xored = this.xor(chainOut, randomizationElements[i + index]);
            chainOut = this.hash(xored);
        }
        return chainOut;
    }

    // xor: Bitwise XOR of two byte arrays
    private xor(a: Uint8Array, b: Uint8Array): Uint8Array {
        if (a.length !== b.length) {
            throw new Error('Arrays must have equal length');
        }
        const result = new Uint8Array(a.length);
        for (let i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    // Generate key pair
    public generateKeyPair(privateSeed: Uint8Array, publicSeed: Uint8Array): {
        publicKey: Uint8Array,
        privateKey: Uint8Array
    } {
        const combinedSeed = new Uint8Array([...privateSeed, ...publicSeed]);
        const privateKey = this.hash(combinedSeed);
        
        const randomizationElements = this.generateRandomizationElements(publicSeed);
        const functionKey = randomizationElements[0];
        
        const publicKeySegments = new Uint8Array(this.numSignatureChunks * this.hashLen);

        for (let i = 0; i < this.numSignatureChunks; i++) {
            const secretKeySegment = this.hash(
                new Uint8Array([...functionKey, ...this.prf(privateKey, i + 1)])
            );
            const segment = this.chain(secretKeySegment, randomizationElements, 0, this.chainLen - 1);
            
            // Copy segment to the correct position in publicKeySegments
            publicKeySegments.set(segment, i * this.hashLen);
        }

        const publicKeyHash = this.hash(publicKeySegments);
        
        // Combine publicSeed and publicKeyHash to form the complete public key
        const publicKey = new Uint8Array([...publicSeed, ...publicKeyHash]);

        return { publicKey, privateKey };
    }

    // sign: Sign a message with a WOTS+ private key. 
    public sign(
        privateKey: Uint8Array, 
        publicSeed: Uint8Array,
        message: Uint8Array
    ): Uint8Array[] {
        if (privateKey.length !== this.hashLen) {
            throw new Error(`private key length must be ${this.hashLen} bytes`);
        }
        if (message.length !== this.messageLen) {
            throw new Error(`message length must be ${this.messageLen} bytes`);
        }

        const randomizationElements = this.generateRandomizationElements(publicSeed);
        const functionKey = randomizationElements[0];
        
        const signature: Uint8Array[] = new Array(this.numSignatureChunks);
        const chainSegments = this.computeMessageHashChainIndexes(message);

        for (let i = 0; i < chainSegments.length; i++) {
            const chainIdx = chainSegments[i];
            const secretKeySegment = this.hash(
                new Uint8Array([...functionKey, ...this.prf(privateKey, i + 1)])
            );
            signature[i] = this.chain(secretKeySegment, randomizationElements, 0, chainIdx);
        }

        return signature;
    }

    // verify: Verify a WOTS+ signature. 
    // 1. The first part of the publicKey is a public seed used to regenerate the randomization elements. (`r` from the paper).
    // 2. The second part of the publicKey is the hash of the NumMessageChunks + NumChecksumChunks public key segments.
    // 3. Convert the Message to "base-w" representation (or base of ChainLen representation).
    // 4. Compute and add the checksum. 
    // 5. Run the chain function on each segment to reproduce each public key segment.
    // 6. Hash all public key segments together to recreate the original public key.
    public verify(
        publicKey: Uint8Array,
        message: Uint8Array,
        signature: Uint8Array[]
    ): boolean {
        if (publicKey.length !== this.publicKeySize) {
            throw new Error(`public key length must be ${this.publicKeySize} bytes`);
        }

        const publicSeed = publicKey.slice(0, this.hashLen);
        const publicKeyHash = publicKey.slice(this.hashLen, this.publicKeySize);
        
        const randomizationElements = this.generateRandomizationElements(publicSeed);
        
        return this.verifyWithRandomizationElements(
            publicKeyHash,
            message,
            signature,
            randomizationElements
        );
    }

    // verify: Verify a WOTS+ signature. 
    // 1. The first part of the publicKey is a public seed used to regenerate the randomization elements. (`r` from the paper).
    // 2. The second part of the publicKey is the hash of the NumMessageChunks + NumChecksumChunks public key segments.
    // 3. Convert the Message to "base-w" representation (or base of ChainLen representation).
    // 4. Compute and add the checksum. 
    // 5. Run the chain function on each segment to reproduce each public key segment.
    // 6. Hash all public key segments together to recreate the original public key.
    public verifyWithRandomizationElements(
        publicKeyHash: Uint8Array,
        message: Uint8Array,
        signature: Uint8Array[],
        randomizationElements: Uint8Array[]
    ): boolean {
        if (publicKeyHash.length !== this.hashLen) {
            throw new Error(`public key hash length must be ${this.hashLen} bytes`);
        }
        if (message.length !== this.messageLen) {
            throw new Error(`message length must be ${this.messageLen} bytes`);
        }
        if (signature.length !== this.numSignatureChunks) {
            throw new Error(`signature length must be ${this.numSignatureChunks}`);
        }

        const chainSegments = this.computeMessageHashChainIndexes(message);
        const publicKeySegments = new Uint8Array(this.numSignatureChunks * this.hashLen);

        // Compute each public key segment. These are done by taking the signature, which is prevChainOut at chainIdx - 1, 
        // and completing the hash chain via the chain function to recompute the public key segment.
        for (let i = 0; i < chainSegments.length; i++) {
            const chainIdx = chainSegments[i];
            const numIterations = this.chainLen - chainIdx - 1;
            const prevChainOut = signature[i];
            
            const segment = this.chain(prevChainOut, randomizationElements, chainIdx, numIterations);
            publicKeySegments.set(segment, i * this.hashLen);
        }

        const computedHash = this.hash(publicKeySegments);
        return BufferUtil.equals(computedHash, publicKeyHash);
    }

    // toBaseW: Convert a message to base-w representation (or base of ChainLen representation)
    // These numbers are used to index into each hash chain which is rooted at a secret key segment and produces
    // a public key segment at the end of the chain. Verification of a signature means using these
    // index into each hash chain to recompute the corresponding public key segment.
    private toBaseW(
        message: Uint8Array, 
        numChunks: number, 
        basew: number[], 
        offset: number
    ): void {
        let index = 0;
        for (let i = 0; i < numChunks; i++) {
            if (i % 2 === 0) {
                basew[offset + i] = (message[index] >> 4) & 0xF;
            } else {
                basew[offset + i] = message[index] & 0xF;
                index++;
            }
        }
    }

    // Compute checksum for the chain indexes
    private checksum(chainIndexes: number[]): void {
        let sum = 0;
        // Sum up the first NUM_MESSAGE_CHUNKS elements
        for (let i = 0; i < this.numMessageChunks; i++) {
            sum += this.chainLen - 1 - chainIndexes[i];
        }

        // Convert checksum to base-w representation
        // Start filling from NUM_MESSAGE_CHUNKS position
        for (let i = 0; i < this.numChecksumChunks; i++) {
            chainIndexes[this.numMessageChunks + i] = (sum >> ((this.numChecksumChunks - 1 - i) * this.lgChainLen)) & (this.chainLen - 1);
        }
    }

    // Compute message hash chain indexes
    // We convert the message to base-w representation (or base of ChainLen representation)
    // We attach the checksum, also in base-w representation, to the end of the hash chain index list. 
    private computeMessageHashChainIndexes(message: Uint8Array): number[] {
        const chainIndexes = new Array(this.numMessageChunks + this.numChecksumChunks).fill(0);
        
        // Convert message to base-w representation
        this.toBaseW(message, this.numMessageChunks, chainIndexes, 0);
        
        // Compute and add checksum
        this.checksum(chainIndexes);
        
        return chainIndexes;
    }
}

// Example usage:
// const wotsPlus = new WOTSPlus(keccak_256); // Uses defaults (32 byte hash, w=16)
// const wotsPlus = new WOTSPlus(keccak_256, 64, 4); // 64 byte hash, w=4
