package cryptorent.xxhash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Implementation of the 32-bit XXHash algorithm.
 */
public class XXHash32 {
    // Prime numbers used in the algorithm
    private static final int PRIME32_1 = 0x9E3779B1;
    private static final int PRIME32_2 = 0x85EBCA77;
    private static final int PRIME32_3 = 0xC2B2AE3D;
    private static final int PRIME32_4 = 0x27D4EB2F;
    private static final int PRIME32_5 = 0x165667B1;

    /**
     * Computes the 32-bit XXHash of the given input byte array with the specified seed.
     *
     * @param input The input data to hash.
     * @param seed  The seed value.
     * @return The 32-bit hash value.
     */
    public static int hash(byte[] input, int seed) {
        return hash(input, input.length, 0, seed);
    }

    public static int hash(byte[] input, int len, int offset, int seed) {
        int hash;
        int bufLimit = offset + len;
        // If the input is longer or equal to 16 bytes, process in 16-byte chunks
        if (bufLimit >= 16) {
            int limit = bufLimit - 16;
            // Initialize four running hash values
            int v1 = seed + PRIME32_1 + PRIME32_2;
            int v2 = seed + PRIME32_2;
            int v3 = seed;
            int v4 = seed - PRIME32_1;

            // Process 16 bytes at a time
            while (offset <= limit) {
                v1 = round(v1, getIntLE(input, offset));
                v2 = round(v2, getIntLE(input, offset + 4));
                v3 = round(v3, getIntLE(input, offset + 8));
                v4 = round(v4, getIntLE(input, offset + 12));
                offset += 16;
            }

            // Combine the four running hash values
            hash = Integer.rotateLeft(v1, 1) +
                    Integer.rotateLeft(v2, 7) +
                    Integer.rotateLeft(v3, 12) +
                    Integer.rotateLeft(v4, 18);
        } else {
            // If input is smaller than 16 bytes, start with seed + PRIME32_5
            hash = seed + PRIME32_5;
        }

        // Add the length of the input to the hash
        hash += len;

        // Process remaining 4-byte chunks
        while (offset + 4 <= bufLimit) {
            hash += getIntLE(input, offset) * PRIME32_3;
            hash = Integer.rotateLeft(hash, 17) * PRIME32_4;
            offset += 4;
        }

        // Process remaining bytes (less than 4)
        while (offset < bufLimit) {
            hash += (input[offset] & 0xFF) * PRIME32_5;
            hash = Integer.rotateLeft(hash, 11) * PRIME32_1;
            offset++;
        }

        // Final mixing of the hash
        hash ^= hash >>> 15;
        hash *= PRIME32_2;
        hash ^= hash >>> 13;
        hash *= PRIME32_3;
        hash ^= hash >>> 16;

        return hash;
    }

    /**
     * Helper method to perform a single round of mixing.
     *
     * @param acc  The accumulator.
     * @param input The input integer.
     * @return The updated accumulator.
     */
    private static int round(int acc, int input) {
        acc += input * PRIME32_2;
        acc = Integer.rotateLeft(acc, 13);
        acc *= PRIME32_1;
        return acc;
    }

    /**
     * Reads a little-endian 4-byte integer from the byte array starting at the given index.
     *
     * @param data   Byte array.
     * @param index  Initial index.
     * @return       An int value composed of 4 bytes.
     */
    private static int getIntLE(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
}
