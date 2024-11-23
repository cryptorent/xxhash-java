package cryptorent.xxhash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class XXH3 {
    public static long hash64(byte[] input, int length, int off, long seed) {
        if (length <= 16)
            return XXH3_len_0to16_64b(input, off, length, seed);
        if (length <= 128)
            return XXH3_len_17to128_64b(input, off, length, seed);
        if (length <= 240)
            return XXH3_len_129to240_64b(input, off, length, seed);
        XXH3_init_accumulators();
        final int nb_blocks = XXH3_hashLong_internal_loop(input, off, length);
        /* last partial block */
        final int nbStripes = ((length - 1) - (block_len * nb_blocks)) / 64;
        final int offBlock = off + block_len * nb_blocks;
        for (int s = 0; s < nbStripes; s++)
            XXH3_accumulate_512(input, offBlock, s);
        XXH3_accumulate_512last(input, off, length);
        final long result64 = XXH3_mergeAccs(length);
        return XXH3_avalanche(result64);
    }


    public static long hash128(final byte[] input, int length, int off, final long seed, long[] result) {
        if (length <= 16)
            return XXH3_len_0to16_128b(input, off, length, result, seed);
        if (length <= 128)
            return XXH3_len_17to128_128b(input, off, length, result, seed);
        if (length <= 240)
            return XXH3_len_129to240_128b(input, off, length, result, seed);
        XXH3_init_accumulators();

        // XXH3_hashLong_internal_loop
        final int nb_blocks = (length - 1) / block_len;
        for (int n = 0; n < nb_blocks; n++) {
            // XXH3_accumulate
            final int offBlock = off + n * block_len;
            for (int s = 0; s < nbStripesPerBlock; s++ ) {
                XXH3_accumulate_512(input, offBlock, s);
            }
            XXH3_scrambleAcc_scalar();
        }

        /* last partial block */
        final int nbStripes = ((length - 1) - (block_len * nb_blocks)) / 64;
        final int offBlock = off + block_len * nb_blocks;
        for (int s = 0; s < nbStripes; s++)
            XXH3_accumulate_512(input, offBlock, s);
        XXH3_accumulate_512last(input, off, length);
        final long low = XXH3_mergeAccs_128(length, result);
        return low;
    }

    private static long XXH3_len_0to16_64b(byte[] input, int off, int length, long seed) {
        // XXH3_len_0to16_64b
        if (length > 8) {
            return XXH3_len_9to16_64b(input, off, length, seed);
        }
        if (length >= 4) {
            return XXH3_len_4to8_64b(input, off, length, seed);
        }
        if (length != 0) {
            return XXH3_len_1to3_64b(input, off, length, seed);
        }
        return XXH64_avalanche(seed ^ LONG_SECRET[7] ^ LONG_SECRET[8]);
    }

    private static long XXH3_len_0to16_128b(byte[] input, int off, int length, long[] result, long seed) {
        // XXH3_len_0to16_128b
        if (length > 8) {
            return XXH3_len_9to16_128b(input, off, length, result, seed);
        }
        if (length >= 4) {
            return XXH3_len_4to8_128b(input, off, length, result, seed);
        }
        if (length != 0) {
            return XXH3_len_1to3_128b(input, off, length, result, seed);
        }
        final long low = XXH64_avalanche(seed ^ LONG_SECRET[8] ^ LONG_SECRET[9]);
        if (null != result) {
            result[0] = low;
            result[1] = XXH64_avalanche(seed ^ LONG_SECRET[10] ^ LONG_SECRET[11]);
        }
        return low;
    }

    private static long XXH3_len_17to128_64b(byte[] input, int off, int length, long seed) {
        long acc = length * PRIME64_1;

        if (length > 32) {
            if (length > 64) {
                if (length > 96) {
                    acc += XXH3_mix16B(seed, input, off + 48, 96);
                    acc += XXH3_mix16B(seed, input, off + length - 64, 112);
                }
                acc += XXH3_mix16B(seed, input, off + 32, 64);
                acc += XXH3_mix16B(seed, input, off + length - 48, 80);
            }
            acc += XXH3_mix16B(seed, input, off + 16, 32);
            acc += XXH3_mix16B(seed, input, off + length - 32, 48);
        }
        acc += XXH3_mix16B(seed, input, off, 0);
        acc += XXH3_mix16B(seed, input, off + length - 16, 16);

        return XXH3_avalanche(acc);
    }

    private static long XXH3_len_17to128_128b(byte[] input, int off, int length, long[] result, long seed) {
        // XXH3_len_17to128_128b
        long acc0 = length * PRIME64_1;
        long acc1 = 0;
        if (length > 32) {
            if (length > 64) {
                if (length > 96) {
                    final long input0 = getLongLE(input, off + 48);
                    final long input1 = getLongLE(input, off + 48 + 8);
                    final long input2 = getLongLE(input, off + length - 64);
                    final long input3 = getLongLE(input, off + length - 64 + 8);
                    acc0 = XXH128_mix32B_once(seed, 96, acc0, input0, input1, input2, input3);
                    acc1 = XXH128_mix32B_once(seed, 96 + 16, acc1, input2, input3, input0, input1);
                }
                final long input0 = getLongLE(input, off + 32);
                final long input1 = getLongLE(input, off + 32 + 8);
                final long input2 = getLongLE(input, off + length - 48);
                final long input3 = getLongLE(input, off + length - 48 + 8);
                acc0 = XXH128_mix32B_once(seed, 64, acc0, input0, input1, input2, input3);
                acc1 = XXH128_mix32B_once(seed, 64 + 16, acc1, input2, input3, input0, input1);
            }
            final long input0 = getLongLE(input, off + 16);
            final long input1 = getLongLE(input, off + 16 + 8);
            final long input2 = getLongLE(input, off + length - 32);
            final long input3 = getLongLE(input, off + length - 32 + 8);
            acc0 = XXH128_mix32B_once(seed, 32, acc0, input0, input1, input2, input3);
            acc1 = XXH128_mix32B_once(seed, 32 + 16, acc1, input2, input3, input0, input1);
        }
        final long input0 = getLongLE(input, off);
        final long input1 = getLongLE(input, off + 8);
        final long input2 = getLongLE(input, off + length - 16);
        final long input3 = getLongLE(input, off + length - 16 + 8);
        acc0 = XXH128_mix32B_once(seed, 0, acc0, input0, input1, input2, input3);
        acc1 = XXH128_mix32B_once(seed, 16, acc1, input2, input3, input0, input1);

        final long low = XXH3_avalanche(acc0 + acc1);
        if (null != result) {
            result[0] = low;
            result[1] = -XXH3_avalanche(acc0 * PRIME64_1 + acc1 * PRIME64_4 + (length - seed) * PRIME64_2);
        }
        return low;
    }


    private static long XXH3_len_129to240_64b(byte[] input, int off, int length, long seed) {
        long acc = length * PRIME64_1;
        final int nbRounds = (int) length / 16;
        int i = 0;
        for (; i < 8; ++i) {
            acc += XXH3_mix16B(seed, input, off + 16 * i, 16 * i);
        }
        acc = XXH3_avalanche(acc);

        for (; i < nbRounds; ++i) {
            acc += XXH3_mix16B_r(seed, input, off + 16 * i, 16 * (i - 8) + 3, 24);
        }

        /* last bytes */
        acc += XXH3_mix16B_r(seed, input, off + length - 16, 136 - 17, 56);
        return XXH3_avalanche(acc);
    }

    private static long XXH3_len_129to240_128b(byte[] input, int off, int length, long[] result, long seed) {
        // XXH3_len_129to240_128b
        final int nbRounds = (int) length / 32;
        long acc0 = length * PRIME64_1;
        long acc1 = 0;
        int i = 0;
        for (; i < 4; ++i) {
            final long input0 = getLongLE(input, off + 32 * i);
            final long input1 = getLongLE(input, off + 32 * i + 8);
            final long input2 = getLongLE(input, off + 32 * i + 16);
            final long input3 = getLongLE(input, off + 32 * i + 24);
            acc0 = XXH128_mix32B_once(seed, 32 * i, acc0, input0, input1, input2, input3);
            acc1 = XXH128_mix32B_once(seed, 32 * i + 16, acc1, input2, input3, input0, input1);
        }
        acc0 = XXH3_avalanche(acc0);
        acc1 = XXH3_avalanche(acc1);

        for (; i < nbRounds; ++i) {
            final long input0 = getLongLE(input, off + 32 * i);
            final long input1 = getLongLE(input, off + 32 * i + 8);
            final long input2 = getLongLE(input, off + 32 * i + 16);
            final long input3 = getLongLE(input, off + 32 * i + 24);
            acc0 = XXH128_mix32B_once_r(seed, 3 + 32 * (i - 4), acc0, input0, input1, input2, input3, 24);
            acc1 = XXH128_mix32B_once_r(seed, 3 + 32 * (i - 4) + 16, acc1, input2, input3, input0, input1, 24);
        }

        // last bytes
        final long input0 = getLongLE(input, off + length - 16);
        final long input1 = getLongLE(input, off + length - 16 + 8);
        final long input2 = getLongLE(input, off + length - 32);
        final long input3 = getLongLE(input, off + length - 32 + 8);
        acc0 = XXH128_mix32B_once_r(-seed, 136 - 17 - 16, acc0, input0, input1, input2, input3, 56);
        acc1 = XXH128_mix32B_once_r(-seed, 136 - 17, acc1, input2, input3, input0, input1, 56);

        final long low = XXH3_avalanche(acc0 + acc1);
        if (null != result) {
            result[0] = low;
            result[1] = -XXH3_avalanche(acc0 * PRIME64_1 + acc1 * PRIME64_4 + (length - seed) * PRIME64_2);
        }
        return low;
    }

    private static void XXH3_init_accumulators() {
        // XXH3_hashLong_64b_internal
        acc_0 = PRIME32_3;
        acc_1 = PRIME64_1;
        acc_2 = PRIME64_2;
        acc_3 = PRIME64_3;
        acc_4 = PRIME64_4;
        acc_5 = PRIME32_2;
        acc_6 = PRIME64_5;
        acc_7 = PRIME32_1;
    }

    private static int XXH3_hashLong_internal_loop(byte[] input, int off, int length) {
        final int nb_blocks = (length - 1) / block_len;
        for (int n = 0; n < nb_blocks; n++) {
            // XXH3_accumulate
            XXH3_accumulate(input, off, n);
            XXH3_scrambleAcc_scalar();
        }
        return nb_blocks;
    }

    // Primes
    private static final long PRIME32_1 = 0x9E3779B1L;   /*!< 0b10011110001101110111100110110001 */
    private static final long PRIME32_2 = 0x85EBCA77L;   /*!< 0b10000101111010111100101001110111 */
    private static final long PRIME32_3 = 0xC2B2AE3DL;   /*!< 0b11000010101100101010111000111101 */

    // Prime constants used in XXH hashing
    private static final long PRIME64_1 = 0x9E3779B185EBCA87L;
    private static final long PRIME64_2 = 0xC2B2AE3D27D4EB4FL;
    private static final long PRIME64_3 = 0x165667B19E3779F9L;
    private static final long PRIME64_4 = 0x85EBCA77C2B2AE63L;
    private static final long PRIME64_5 = 0x27D4EB2F165667C5L;

    private static final int nbStripesPerBlock = (192 - 64) / 8;
    private static final int block_len = 64 * nbStripesPerBlock;

    private static long acc_0, acc_1, acc_2, acc_3, acc_4, acc_5, acc_6, acc_7;

    /*! Pseudorandom XXH3_kSecret taken directly from FARSH. */
    private static final long[] LONG_SECRET = {
            0xbe4ba423396cfeb8L, 0x1cad21f72c81017cL, 0xdb979083e96dd4deL, 0x1f67b3b7a4a44072L,
            0x78e5c0cc4ee679cbL, 0x2172ffcc7dd05a82L, 0x8e2443f7744608b8L, 0x4c263a81e69035e0L,
            0xcb00c391bb52283cL, 0xa32e531b8b65d088L, 0x4ef90da297486471L, 0xd8acdea946ef1938L,
            0x3f349ce33f76faa8L, 0x1d4f0bc7c7bbdcf9L, 0x3159b4cd4be0518aL, 0x647378d9c97e9fc8L,
            0xc3ebd33483acc5eaL, 0xeb6313faffa081c5L, 0x49daf0b751dd0d17L, 0x9e68d429265516d3L,
            0xfca1477d58be162bL, 0xce31d07ad1b8f88fL, 0x280416958f3acb45L, 0x7e404bbbcafbd7afL,
    };

    private static void XXH3_accumulate_512(byte[] input, int offBlock, int s) {
        // XXH3_accumulate_512
        final int offStripe = offBlock + s * 64;
        final int offSec = s * 8;
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 0);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 1);
            final long data_key_0 = data_val_0 ^ LONG_SECRET[s];
            final long data_key_1 = data_val_1 ^ LONG_SECRET[s + 1];
            /* swap adjacent lanes */
            acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 2);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 3);
            final long data_key_0 = data_val_0 ^ LONG_SECRET[s + 2];
            final long data_key_1 = data_val_1 ^ LONG_SECRET[s + 3];
            /* swap adjacent lanes */
            acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 4);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 5);
            final long data_key_0 = data_val_0 ^ LONG_SECRET[s + 4];
            final long data_key_1 = data_val_1 ^ LONG_SECRET[s + 5];
            /* swap adjacent lanes */
            acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 6);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 7);
            final long data_key_0 = data_val_0 ^ LONG_SECRET[s + 6];
            final long data_key_1 = data_val_1 ^ LONG_SECRET[s + 7];
            /* swap adjacent lanes */
            acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
    }

    private static void XXH3_accumulate_512last(byte[] input, int off, int length) {
        /* last stripe */
        final int offStripe = off + length - 64;
        final int offSec = 192 - 64 - 7;
        {
            final long data_val_0 = getLongLE(input, offStripe);
            final long data_val_1 = getLongLE(input, offStripe + 8);
            final long data_key_0 = data_val_0 ^ (LONG_SECRET[offSec / 8] >>> 8 ^ LONG_SECRET[offSec / 8 + 1] << 56);
            final long data_key_1 = data_val_1 ^ (LONG_SECRET[offSec / 8 + 1] >>> 8 ^ LONG_SECRET[offSec / 8 + 2] << 56);
            /* swap adjacent lanes */
            acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 2);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 3);
            final long data_key_0 = data_val_0 ^ (LONG_SECRET[offSec / 8 + 2] >>> 8 ^ LONG_SECRET[offSec / 8 + 3] << 56);
            final long data_key_1 = data_val_1 ^ (LONG_SECRET[offSec / 8 + 3] >>> 8 ^ LONG_SECRET[offSec / 8 + 4] << 56);
            /* swap adjacent lanes */
            acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 4);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 5);
            final long data_key_0 = data_val_0 ^ (LONG_SECRET[offSec / 8 + 4] >>> 8 ^ LONG_SECRET[offSec / 8 + 5] << 56);
            ;
            final long data_key_1 = data_val_1 ^ (LONG_SECRET[offSec / 8 + 5] >>> 8 ^ LONG_SECRET[offSec / 8 + 6] << 56);
            /* swap adjacent lanes */
            acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = getLongLE(input, offStripe + 8 * 6);
            final long data_val_1 = getLongLE(input, offStripe + 8 * 7);
            final long data_key_0 = data_val_0 ^ (LONG_SECRET[offSec / 8 + 6] >>> 8 ^ LONG_SECRET[offSec / 8 + 7] << 56);
            final long data_key_1 = data_val_1 ^ (LONG_SECRET[offSec / 8 + 7] >>> 8 ^ LONG_SECRET[offSec / 8 + 8] << 56);
            /* swap adjacent lanes */
            acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
    }

    private static long XXH3_mergeAccs(int length) {
        final long result64 = length * PRIME64_1
                + XXH3_mix2Accs_r(acc_0, acc_1, 1, 24)
                + XXH3_mix2Accs_r(acc_2, acc_3, 3, 24)
                + XXH3_mix2Accs_r(acc_4, acc_5, 5, 24)
                + XXH3_mix2Accs_r(acc_6, acc_7, 7, 24);
        return result64;
    }

    private static long XXH3_mergeAccs_128(int length, long[] result) {
        // XXH3_mergeAccs
        final long low = XXH3_avalanche(length * PRIME64_1
                + XXH3_mix2Accs_r(acc_0, acc_1, 1, 24)
                + XXH3_mix2Accs_r(acc_2, acc_3, 3, 24)
                + XXH3_mix2Accs_r(acc_4, acc_5, 5, 24)
                + XXH3_mix2Accs_r(acc_6, acc_7, 7, 24));
        if (null != result) {
            result[0] = low;
            result[1] = XXH3_avalanche(~(length * PRIME64_2)
                    + XXH3_mix2Accs_r(acc_0, acc_1, 14, 40)
                    + XXH3_mix2Accs_r(acc_2, acc_3, 16, 40)
                    + XXH3_mix2Accs_r(acc_4, acc_5, 18, 40)
                    + XXH3_mix2Accs_r(acc_6, acc_7, 20, 40));
        }
        return low;
    }


    private static long XXH3_avalanche(long h64) {
        h64 ^= h64 >>> 37;
        h64 *= 0x165667919E3779F9L;
        return h64 ^ (h64 >>> 32);
    }

    private static long XXH64_avalanche(long h64) {
        h64 ^= h64 >>> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >>> 29;
        h64 *= PRIME64_3;
        return h64 ^ (h64 >>> 32);
    }

    private static void XXH3_scrambleAcc_scalar() {
        // XXH3_scrambleAcc_scalar
        final int offSec = 192 - 64;
        final int offSec8 = offSec / 8;
        acc_0 = (acc_0 ^ (acc_0 >>> 47) ^ LONG_SECRET[offSec8 + 0]) * PRIME32_1;
        acc_1 = (acc_1 ^ (acc_1 >>> 47) ^ LONG_SECRET[offSec8 + 1]) * PRIME32_1;
        acc_2 = (acc_2 ^ (acc_2 >>> 47) ^ LONG_SECRET[offSec8 + 2]) * PRIME32_1;
        acc_3 = (acc_3 ^ (acc_3 >>> 47) ^ LONG_SECRET[offSec8 + 3]) * PRIME32_1;
        acc_4 = (acc_4 ^ (acc_4 >>> 47) ^ LONG_SECRET[offSec8 + 4]) * PRIME32_1;
        acc_5 = (acc_5 ^ (acc_5 >>> 47) ^ LONG_SECRET[offSec8 + 5]) * PRIME32_1;
        acc_6 = (acc_6 ^ (acc_6 >>> 47) ^ LONG_SECRET[offSec8 + 6]) * PRIME32_1;
        acc_7 = (acc_7 ^ (acc_7 >>> 47) ^ LONG_SECRET[offSec8 + 7]) * PRIME32_1;
    }

    private static long XXH3_len_9to16_64b(byte[] input, int off, int length, long seed) {
        // XXH3_len_9to16_64b
        final long bitflip1 = (LONG_SECRET[3] ^ LONG_SECRET[4]) + seed;
        final long bitflip2 = (LONG_SECRET[5] ^ LONG_SECRET[6]) - seed;
        final long input_lo = getLongLE(input, off) ^ bitflip1;
        final long input_hi = getLongLE(input, off + length - 8) ^ bitflip2;
        final long acc = length + Long.reverseBytes(input_lo) + input_hi + unsignedLongMulXorFold(input_lo, input_hi);
        return XXH3_avalanche(acc);
    }

    private static long XXH3_len_9to16_128b(byte[] input, int off, int length, long[] result, long seed) {
        // XXH3_len_9to16_128b
        final long bitflipl = (LONG_SECRET[4] ^ LONG_SECRET[5]) - seed;
        final long bitfliph = (LONG_SECRET[6] ^ LONG_SECRET[7]) + seed;
        long input_hi = getLongLE(input, off + length - 8);
        final long input_lo = getLongLE(input, off) ^ input_hi ^ bitflipl;
        long m128_lo = input_lo * PRIME64_1;
        long m128_hi = unsignedLongMulHigh(input_lo, PRIME64_1);
        m128_lo += (long) (length - 1) << 54;
        input_hi ^= bitfliph;
        m128_hi += input_hi + unsignedInt((int) input_hi) * (PRIME32_2 - 1);
        m128_lo ^= Long.reverseBytes(m128_hi);

        final long low = XXH3_avalanche(m128_lo * PRIME64_2);
        if (null != result) {
            result[0] = low;
            result[1] = XXH3_avalanche(unsignedLongMulHigh(m128_lo, PRIME64_2) + m128_hi * PRIME64_2);
        }
        return low;
    }

    private static long XXH3_len_4to8_64b(byte[] input, int off, int length, long seed) {
        long s = seed ^ Long.reverseBytes(seed & 0xFFFFFFFFL);
        final long input1 = (long) getIntLE(input, off); // high int will be shifted
        final long input2 = unsignedInt(getIntLE(input, off + length - 4));
        final long bitflip = (LONG_SECRET[1] ^ LONG_SECRET[2]) - s;
        final long keyed = (input2 + (input1 << 32)) ^ bitflip;
        return XXH3_rrmxmx(keyed, length);
    }

    private static long XXH3_len_4to8_128b(byte[] input, int off, int length, long[] result, long seed) {
        // XXH3_len_4to8_128b
        long s = seed ^ Long.reverseBytes(seed & 0xFFFFFFFFL);
        final long input_lo = unsignedInt(getIntLE(input, off));
        final long input_hi = (long) getIntLE(input, off + length - 4); // high int will be shifted

        final long bitflip = (LONG_SECRET[2] ^ LONG_SECRET[3]) + s;
        final long keyed = (input_lo + (input_hi << 32)) ^ bitflip;
        final long pl = PRIME64_1 + ((long) length << 2); // Shift len to the left to ensure it is even, this avoids even multiplies.
        long m128_lo = keyed * pl;
        long m128_hi = unsignedLongMulHigh(keyed, pl);
        m128_hi += (m128_lo << 1);
        m128_lo ^= (m128_hi >>> 3);

        m128_lo ^= m128_lo >>> 35;
        m128_lo *= 0x9FB21C651E98DF25L;
        m128_lo ^= m128_lo >>> 28;

        if (null != result) {
            result[0] = m128_lo;
            result[1] = XXH3_avalanche(m128_hi);
        }
        return m128_lo;
    }

    private static long XXH3_len_1to3_64b(byte[] input, int off, int length, long seed) {
        final int c1 = unsignedByte(input[off]);
        final int c2 = input[off + (length >> 1)]; // high 3 bytes will be shifted
        final int c3 = unsignedByte(input[off + length - 1]);
        final int comb = (c1 << 16) | (c2 << 24) | c3 | ((int) length << 8);
        final long combined = unsignedInt(comb);
        final long bitflip = xorHalfs(LONG_SECRET[0]) + seed;
        return XXH64_avalanche(combined ^ bitflip);
    }

    private static long XXH3_len_1to3_128b(byte[] input, int off, int length, long[] result, long seed) {
        final int c1 = unsignedByte(input[off]);
        final int c2 = input[off + (length >> 1)]; // high 3 bytes will be shifted
        final int c3 = unsignedByte(input[off + length - 1]);
        final int comb = (c1 << 16) | (c2 << 24) | c3 | ((int) length << 8);
        final long combined = unsignedInt(comb);
        final long bitflip = xorHalfs(LONG_SECRET[0]) + seed;
        final long low = XXH64_avalanche(combined ^ bitflip);
        final long bitfliph = xorHalfs(LONG_SECRET[1]) - seed;
        final int combinedh = Integer.rotateLeft(Integer.reverseBytes(comb), 13);
        if (result != null) {
            result[0] = low;
            result[1] = XXH64_avalanche(unsignedInt(combinedh) ^ bitfliph);
        }
        return low;
    }

    private static long XXH3_mix16B(final long seed, byte[] input, int offIn, int offSec) {
        final long input_lo = getLongLE(input, offIn);
        final long input_hi = getLongLE(input, offIn + 8);
        return unsignedLongMulXorFold(
                input_lo ^ (LONG_SECRET[offSec / 8] + seed),
                input_hi ^ (LONG_SECRET[offSec / 8 + 1] - seed)
        );
    }

    private static long XXH3_mix16B_r(final long seed, byte[] input, int offIn, int offSec, int r) {
        final long input_lo = getLongLE(input, offIn);
        final long input_hi = getLongLE(input, offIn + 8);
        return unsignedLongMulXorFold(
                input_lo ^ ((LONG_SECRET[offSec / 8] >>> r ^ LONG_SECRET[offSec / 8 + 1] << (64-r)) + seed),
                input_hi ^ ((LONG_SECRET[offSec / 8 + 1] >>> r ^ LONG_SECRET[offSec / 8 + 2] << (64-r)) - seed)
        );
    }

    /*
     * A bit slower than XXH3_mix16B, but handles multiply by zero better.
     */
    private static long XXH128_mix32B_once(final long seed, int offSec, long acc, final long input0, final long input1, final long input2, final long input3) {
        acc += unsignedLongMulXorFold(
                input0 ^ (LONG_SECRET[offSec / 8] + seed),
                input1 ^ (LONG_SECRET[offSec / 8 + 1] - seed));
        return acc ^ (input2 + input3);
    }

    private static long XXH128_mix32B_once_r(final long seed, int offSec, long acc, final long input0, final long input1, final long input2, final long input3, int r) {
        acc += unsignedLongMulXorFold(
                input0 ^ ((LONG_SECRET[offSec / 8] >>> r ^ LONG_SECRET[offSec / 8 + 1] << (64-r)) + seed),
                input1 ^ ((LONG_SECRET[offSec / 8 + 1] >>> r ^ LONG_SECRET[offSec / 8 + 2] << (64-r)) - seed)
        );
        return acc ^ (input2 + input3);
    }

    private static long XXH3_mix2Accs_r(final long acc_lh, final long acc_rh, final int offSec, int r) {
        return unsignedLongMulXorFold(
                acc_lh ^ (LONG_SECRET[offSec] >>> r) ^ (LONG_SECRET[offSec + 1] << (64 - r)),
                acc_rh ^ (LONG_SECRET[offSec + 1] >>> r) ^ (LONG_SECRET[offSec + 2] << (64 - r)));
    }

    private static void XXH3_accumulate(byte[] input, int off, int n) {
        final int offBlock = off + n * block_len;
        for (int s = 0; s < nbStripesPerBlock; s++)
            XXH3_accumulate_512(input, offBlock, s);
    }

    private static long XXH3_rrmxmx(long h64, final int length) {
        h64 ^= Long.rotateLeft(h64, 49) ^ Long.rotateLeft(h64, 24);
        h64 *= 0x9FB21C651E98DF25L;
        h64 ^= (h64 >>> 35) + length;
        h64 *= 0x9FB21C651E98DF25L;
        return h64 ^ (h64 >>> 28);
    }

    private static int getIntLE(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static long getLongLE(byte[] data, int index) {
        return ByteBuffer.wrap(data, index, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    private static long unsignedLongMulHigh(final long lhs, final long rhs) {
        // The Grade School method of multiplication is a hair faster in Java, primarily used here
        // because the implementation is simpler.
        final long lhs_l = lhs & 0xFFFFFFFFL;
        final long lhs_h = lhs >>> 32;
        final long rhs_l = rhs & 0xFFFFFFFFL;
        final long rhs_h = rhs >>> 32;
        final long lo_lo = lhs_l * rhs_l;
        final long hi_lo = lhs_h * rhs_l;
        final long lo_hi = lhs_l * rhs_h;
        final long hi_hi = lhs_h * rhs_h;

        // Add the products together. This will never overflow.
        final long cross = (lo_lo >>> 32) + (hi_lo & 0xFFFFFFFFL) + lo_hi;
        final long upper = (hi_lo >>> 32) + (cross >>> 32) + hi_hi;
        return upper;
    }

    private static long unsignedLongMulXorFold(final long lhs, final long rhs) {
        // The Grade School method of multiplication is a hair faster in Java, primarily used here
        // because the implementation is simpler.
        final long lhs_l = lhs & 0xFFFFFFFFL;
        final long lhs_h = lhs >>> 32;
        final long rhs_l = rhs & 0xFFFFFFFFL;
        final long rhs_h = rhs >>> 32;
        final long lo_lo = lhs_l * rhs_l;
        final long hi_lo = lhs_h * rhs_l;
        final long lo_hi = lhs_l * rhs_h;
        final long hi_hi = lhs_h * rhs_h;

        // Add the products together. This will never overflow.
        final long cross = (lo_lo >>> 32) + (hi_lo & 0xFFFFFFFFL) + lo_hi;
        final long upper = (hi_lo >>> 32) + (cross >>> 32) + hi_hi;
        final long lower = (cross << 32) | (lo_lo & 0xFFFFFFFFL);
        return lower ^ upper;
    }

    static long unsignedInt(int i) {
        return i & 0xFFFFFFFFL;
    }

    static long xorHalfs(long hl) {
        return (hl & 0xffffffffL) ^ (hl >>> 32);
    }

    static int unsignedByte(int b) {
        return b & 0xFF;
    }
}
