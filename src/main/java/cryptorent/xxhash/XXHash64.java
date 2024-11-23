package cryptorent.xxhash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Implementation of the 64-bit XXHash algorithm.
 */
public class XXHash64 {
    // Prime numbers used in the algorithm
    private static final long PRIME64_1 = 0x9E3779B185EBCA87L;
    private static final long PRIME64_2 = 0xC2B2AE3D27D4EB4FL;
    private static final long PRIME64_3 = 0x165667B19E3779F9L;
    private static final long PRIME64_4 = 0x85EBCA77C2B2AE63L;
    private static final long PRIME64_5 = 0x27D4EB2F165667C5L;

    /**
     * Computes the 64-bit XXHash of the given input byte array with the specified seed.
     *
     * @param input The input data to hash.
     * @param seed  The seed value.
     * @return The 64-bit hash value.
     */
    public static long hash(byte[] input, long seed) {
        return hash(input, input.length, 0, seed);
    }

    public static long hash(byte[] input, int len, int offset, long seed) {
        long hash;
        int bufLimit = offset + len;
        // If the input is longer or equal to 32 bytes, process in 32-byte chunks
        if (bufLimit >= 32) {
            int limit = bufLimit - 32;
            long v1 = seed + PRIME64_1 + PRIME64_2;
            long v2 = seed + PRIME64_2;
            long v3 = seed + 0;
            long v4 = seed - PRIME64_1;

            // Process 32 bytes at a time
            while (offset <= limit) {
                v1 = round(v1, getLongLE(input, offset));
                v2 = round(v2, getLongLE(input, offset + 8));
                v3 = round(v3, getLongLE(input, offset + 16));
                v4 = round(v4, getLongLE(input, offset + 24));
                offset += 32;
            }

            // Combine the four running hash values
            hash = Long.rotateLeft(v1, 1) +
                    Long.rotateLeft(v2, 7) +
                    Long.rotateLeft(v3, 12) +
                    Long.rotateLeft(v4, 18);

            hash = mergeRound(hash, v1);
            hash = mergeRound(hash, v2);
            hash = mergeRound(hash, v3);
            hash = mergeRound(hash, v4);
        } else {
            // If input is smaller than 32 bytes, start with seed + PRIME64_5
            hash = seed + PRIME64_5;
        }

        // Add the length of the input to the hash
        hash += len;

        // Processing 8-byte blocks
        while (offset + 8 <= bufLimit) {
            long k1 = getLongLE(input, offset);
            k1 *= PRIME64_2;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= PRIME64_1;
            hash ^= k1;
            hash = Long.rotateLeft(hash, 27) * PRIME64_1 + PRIME64_4;
            offset += 8;
        }

        // Processing 4-byte blocks
        while (offset + 4 <= bufLimit) {
            hash ^= (getIntLE(input, offset) & 0xFFFFFFFFL) * PRIME64_1;
            hash = Long.rotateLeft(hash, 23) * PRIME64_2 + PRIME64_3;
            offset += 4;
        }

        // Process remaining bytes (less than 8)
        while (offset < bufLimit) {
            hash ^= (input[offset] & 0xFFL) * PRIME64_5;
            hash = Long.rotateLeft(hash, 11) * PRIME64_1;
            offset++;
        }

        // Final mixing of the hash
        hash ^= hash >>> 33;
        hash *= PRIME64_2;
        hash ^= hash >>> 29;
        hash *= PRIME64_3;
        hash ^= hash >>> 32;

        return hash;
    }

    /**
     * Helper method to perform a single round of mixing.
     *
     * @param acc   The accumulator.
     * @param input The input long.
     * @return The updated accumulator.
     */
    private static long round(long acc, long input) {
        acc += input * PRIME64_2;
        acc = Long.rotateLeft(acc, 31);
        acc *= PRIME64_1;
        return acc;
    }

    /**
     * Helper method to merge a running hash value into the final hash.
     *
     * @param hash The current hash.
     * @param v    The running hash value to merge.
     * @return The updated hash.
     */
    private static long mergeRound(long hash, long v) {
        hash ^= round(0, v);
        hash = hash * PRIME64_1 + PRIME64_4;
        return hash;
    }

    /**
     * Reads a little-endian 8-byte long from the byte array starting at the given index.
     *
     * @param data  The byte array.
     * @param index The starting index.
     * @return The long value.
     */
    private static long getLongLE(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    /**
     * Reads 4 bytes from a data array in little-endian order.
     *
     * @param data   Byte array.
     * @param index  Initial index.
     * @return       An int value composed of 4 bytes.
     */
    private static int getIntLE(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
}