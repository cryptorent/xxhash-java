package cryptorent.xxhash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XXHash32Test {
    @Test
    void test() {
        String input = "test";
        byte[] data = input.getBytes();
        int seed = 0;
        int hashValue = XXHash32.hash(data, seed);
        assertEquals(0x3E2023CF, hashValue);
    }

    @Test
    void testLen20() {
        String input = "01234567890123456789";
        byte[] data = input.getBytes();
        int seed = 0;
        int hashValue = XXHash32.hash(data, seed);
        assertEquals(0x7183E10C, hashValue);
    }
}
