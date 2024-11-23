package cryptorent.xxhash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XXHash64Test {
    @Test
    void test() {
        String input = "test";
        byte[] data = input.getBytes();
        long seed = 0;
        long hashValue = XXHash64.hash(data, seed);
        assertEquals(0x4FDCCA5DDB678139L, hashValue);
    }

    @Test
    void testLen20() {
        String input = "01234567890123456789";
        byte[] data = input.getBytes();
        long seed = 0;
        long hashValue = XXHash64.hash(data, seed);
        assertEquals(0x2D071F530B4E5DCCL, hashValue);
    }
}
