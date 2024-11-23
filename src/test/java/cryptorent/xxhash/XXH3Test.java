package cryptorent.xxhash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XXH3Test {
    byte[] gen(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) ((i % 10) + (byte)'0');
        }
        return data;
    }

    @Test
    void test3() {
        byte[] data = gen(3);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x8ED2B2F360965D90L, hash);
    }

    @Test
    void test4() {
        byte[] data = gen(4);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x8AA92DA18EDB594BL, hash);
    }

    @Test
    void test5() {
        byte[] data = gen(5);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x2774A76A01B160F2L, hash);
    }

    @Test
    void test7() {
        byte[] data = gen(7);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0xA46E0EE310EE347FL, hash);
    }

    @Test
    void test8() {
        byte[] data = gen(8);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x1808E40D6723F646L, hash);
    }

    @Test
    void test9() {
        byte[] data = gen(9);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x3B5293CE9B5BD7D7L, hash);
    }

    @Test
    void test15() {
        byte[] data = gen(15);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x21591A582630AC31L, hash);
    }

    @Test
    void test16() {
        byte[] data = gen(16);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x84ABDF53E8A03697L, hash);
    }

    @Test
    void test17() {
        byte[] data = gen(17);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x33C12B721FDB9F24L, hash);
    }

    @Test
    void test31() {
        byte[] data = gen(31);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x0DFF783D121B4C10L, hash);
    }

    @Test
    void test32() {
        byte[] data = gen(32);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x02D69C9048AECFF4L, hash);
    }

    @Test
    void test33() {
        byte[] data = gen(33);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x4E24F7574F8770C4L, hash);
    }

    @Test
    void test63() {
        byte[] data = gen(63);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0xA6834801E298895AL, hash);
    }

    @Test
    void test64() {
        byte[] data = gen(64);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x9D748132BB6ED89EL, hash);
    }

    @Test
    void test65() {
        byte[] data = gen(65);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x68B359210642FECBL, hash);
    }

    @Test
    void test127() {
        byte[] data = gen(127);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0xE4A0A219D848756EL, hash);
    }

    @Test
    void test128() {
        byte[] data = gen(128);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x2F83C9540EE32C9CL, hash);
    }

    @Test
    void test129() {
        byte[] data = gen(129);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x629D0D760A7CA820L, hash);
    }

    @Test
    void test239() {
        byte[] data = gen(239);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0xA2B70FCA8EAD1F78L, hash);
    }

    @Test
    void test240() {
        byte[] data = gen(240);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x73697F089085EABDL, hash);
    }

    @Test
    void test241() {
        byte[] data = gen(241);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x367D0CE95644ADE5L, hash);
    }

    @Test
    void test480() {
        byte[] data = gen(480);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x5D7C066A8DCE428EL, hash);
    }

    @Test
    void test2005() {
        byte[] data = gen(2005);
        long hash = XXH3.hash64(data, data.length, 0, 0);
        assertEquals(0x0CFABA171612493EL, hash);
    }
}
