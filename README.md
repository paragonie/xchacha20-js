# XChaCha20 (JavaScript)

This is a pure JavaScript implementation of XChaCha20 (and therefore ChaCha20
and HChaCha20), for use in polyfill libraries.

## Installing this Library

```
npm install xchacha20-js
```

## Using this Library

```javascript
const XChaCha20 = require('xchacha20-js');

let xcha20 = new XChaCha20;
let message = "test message";
let key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
let nonce = Buffer.from('404142434445464748494a4b4c4d4e4f5051525354555658', 'hex');

let blockCounter = 1; // Optional, defaults to 1 per the RFC
let ciphertext = xcha20.encrypt(message, nonce, key, blockCounter);
let plaintext = xcha20.decrypt(ciphertext, nonce, key, blockCounter);
``` 