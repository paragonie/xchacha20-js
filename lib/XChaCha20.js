"use strict";

const HChaCha20 = require('./HChaCha20');

module.exports = class XChaCha20
{
    constructor()
    {
        this.hchacha20 = new HChaCha20();
    }

    /**
     *
     * @param {Number} length
     * @param {string|Buffer} key
     * @param {string|Buffer} nonce
     * @param {Number|Buffer} counter
     */
    streamBytes(length, key, nonce, counter = 1)
    {
        let outnonce = Buffer.alloc(12, 0);
        nonce.slice(16).copy(outnonce, 4);
        return this.hchacha20.ietfStream(
            length,
            this.hchacha20.hChaCha20Bytes(
                nonce.slice(0, 16),
                key
            ),
            outnonce,
            counter
        );
    }

    /**
     * Encryption (defers to streamXorIc)
     *
     * @param {string|Buffer} message
     * @param {string|Buffer} nonce
     * @param {string|Buffer} key
     * @param {Number|Buffer} counter
     */
    encrypt(message, nonce, key, counter = 1)
    {
        return this.streamXorIc(message, nonce, key, counter);
    }

    /**
     * Decryption (defers to streamXorIc)
     *
     * @param {string|Buffer} message
     * @param {string|Buffer} nonce
     * @param {string|Buffer} key
     * @param {Number|Buffer} counter
     */
    decrypt(message, nonce, key, counter = 1)
    {
        return this.streamXorIc(message, nonce, key, counter);
    }

    /**
     * @param {string|Buffer} message
     * @param {string|Buffer} nonce
     * @param {string|Buffer} key
     * @param {Number|Buffer} counter
     */
    streamXorIc(message, nonce, key, counter = 1)
    {
        if (key.length !== 32) {
            throw new Error('Key must be 32 bytes')
        }
        if (nonce.length !== 24) {
            throw new Error('Nonce must be 24 bytes')
        }
        let outnonce = Buffer.alloc(12, 0);
        nonce.slice(16).copy(outnonce, 4);
        return this.hchacha20.ietfStreamXorIc(
            message,
            outnonce,
            this.hchacha20.hChaCha20Bytes(
                nonce.slice(0, 16),
                key
            ),
            counter
        );
    }
};
