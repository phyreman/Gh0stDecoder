# Gh0stDecoder
NodeJS decoder for Gh0st RAT packets

# Usage
```javascript
const { decode_Gh0st } = require("./Gh0stDecoder.js");
const { unzipSync } = require("node:zlib");

/* Incoming network packet...set it however your program requires */
const packet; // This needs to be a Buffer

// First 5 bytes of the payload should be "Gh0st"
const magicBytes = packet.toString("utf8", 0, 5);
if (magicBytes !== "Gh0st") return;

// Next 4 bytes are the size of the compressed payload
const compressedSize = packet.readUInt32LE(5);

// Next 4 bytes after that are the size of the uncompressed payload
const uncompressedSize = packet.readUInt32LE(9);

// After that comes the ZLIB zip-compressed (default compression) payload
const compressedPayload = packet.subArray(13);
const uncompressedPayload = unzipSync(uncompressedPayload);

const decodedPayload = decode_Gh0st(uncompressedPayload);

console.log(decodedPayload);
```