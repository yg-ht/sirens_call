#!/usr/bin/env node

const { Command } = require('commander');
const program = new Command();

// === Layer 1 ===
function decodeSignal(signal) {
    const cleaned = cleanSignal(signal); // Layer 2
    const interpreted = interpretSignal(cleaned); // Layer 2
    const message = translateToHuman(interpreted); // Layer 2
    return message;
}

// === Layer 2 ===
function cleanSignal(signal) {
    return signal
        .replace(/[^01]/g, '')  // Remove noise
        .slice(0, 16);          // Truncate to known signal size
}

function interpretSignal(cleaned) {
    const binaryGroups = groupBits(cleaned); // Layer 3
    return binaryGroups.map(parseChunk);     // Layer 3
}

function translateToHuman(bitsArray) {
    return bitsArray.map(toChar).join('');
}

// === Layer 3 ===
function groupBits(bits) {
    const groupSize = 4;
    const groups = [];
    for (let i = 0; i < bits.length; i += groupSize) {
        groups.push(bits.slice(i, i + groupSize));
    }
    return groups;
}

function parseChunk(chunk) {
    return parseInt(chunk, 2); // Binary to integer
}

function toChar(num) {
    const map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return map[num % map.length];
}

// === Commander CLI ===
program
    .name('alien-decoder')
    .description('Decodes a simulated alien binary signal')
    .version('0.1.0');

program
    .command('decode')
    .description('Decode a binary alien signal')
    .argument('<signal>', 'raw binary signal with noise')
    .action((signal) => {
        const result = decodeSignal(signal);
        console.log(`Decoded message: ${result}`);
    });

program.parse(process.argv);
