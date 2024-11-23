package cryptorent.xxhash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XXH3Test128 {
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
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x8ED2B2F360965D90L, result[0]);
        assertEquals(0x93AEC821685CEBC1L, result[1]);

    }

    @Test
    void test4() {
        byte[] data = gen(4);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x824B77D5917B737BL, result[0]);
        assertEquals(0xE7F00C8D576B45EEL, result[1]);
    }

    @Test
    void test5() {
        byte[] data = gen(5);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0xBD3F18DBEFF4DD2EL, result[0]);
        assertEquals(0x44F0AD485D404389L, result[1]);
    }

    @Test
    void test7() {
        byte[] data = gen(7);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x78CF37FD0BC183C4L, result[0]);
        assertEquals(0x6343E550F79608E2L, result[1]);
    }

    @Test
    void test8() {
        byte[] data = gen(8);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0xF455A8E446810217L, result[0]);
        assertEquals(0x647579EA30E43A75L, result[1]);
    }

    @Test
    void test9() {
        byte[] data = gen(9);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0xE23A7F36C9118966L, result[0]);
        assertEquals(0x7ED631159E915EA8L, result[1]);
    }

    @Test
    void test15() {
        byte[] data = gen(15);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0xAF786D8D0A291815L, result[0]);
        assertEquals(0xBC9BF1DAE2F88023L, result[1]);
    }

    @Test
    void test16() {
        byte[] data = gen(16);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x02CD2CF2F8106579L, result[0]);
        assertEquals(0x0CEE8790D00E20D6L, result[1]);
    }

    @Test
    void test17() {
        byte[] data = gen(17);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0xD99E120F29EB2C61L, result[0]);
        assertEquals(0xFCF0446565AF98B2L, result[1]);
    }

    @Test
    void test31() {
        byte[] data = gen(31);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x9D14CF7B6A25F0C9L, result[0]);
        assertEquals(0xE7A25DB10277C620L, result[1]);
    }

    @Test
    void test32() {
        byte[] data = gen(32);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x986394F7381DBDA1L, result[0]);
        assertEquals(0xA7E6C59C8CC00FBAL, result[1]);
    }

    @Test
    void test33() {
        byte[] data = gen(33);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0xA843CBD4ADDFF935L, result[0]);
        assertEquals(0x82F5AFD9B55F8C17L, result[1]);
    }

    @Test
    void test63() {
        byte[] data = gen(63);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x01A093053173FC85L, result[0]);
        assertEquals(0x7AF0EA2DD7BDB4BEL, result[1]);
    }

    @Test
    void test64() {
        byte[] data = gen(64);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x9D7EC9B2F45AD55AL, result[0]);
        assertEquals(0xDEA3ED0E2A3394FBL, result[1]);
    }

    @Test
    void test65() {
        byte[] data = gen(65);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x9240CB55D3B1AFEEL, result[0]);
        assertEquals(0x1D374C5568DEFE84L, result[1]);
    }

    @Test
    void test127() {
        byte[] data = gen(127);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x77660A8B8B553CB0L, result[0]);
        assertEquals(0xA7B43583DDFC9393L, result[1]);
    }

    @Test
    void test128() {
        byte[] data = gen(128);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x641C7F4E2D805D60L, result[0]);
        assertEquals(0x56DFF7559D5811F4L, result[1]);
    }

    @Test
    void test129() {
        byte[] data = gen(129);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x33260DFE90E8D890L, result[0]);
        assertEquals(0x18A2A06F270418CDL, result[1]);
    }

    @Test
    void test239() {
        byte[] data = gen(239);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x3392DC4E747D50E8L, result[0]);
        assertEquals(0x218D8BE4E87133CFL, result[1]);
    }

    @Test
    void test240() {
        byte[] data = gen(240);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x2262F4D2EAF15AEAL, result[0]);
        assertEquals(0x8EEFE86FDB1B9E1EL, result[1]);
    }

    @Test
    void test241() {
        byte[] data = gen(241);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x367D0CE95644ADE5L, result[0]);
        assertEquals(0x8B8BE89226108C58L, result[1]);
    }

    @Test
    void test480() {
        byte[] data = gen(480);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x5D7C066A8DCE428EL, result[0]);
        assertEquals(0x3F26CE491413FCE5L, result[1]);
    }

    @Test
    void test2005() {
        byte[] data = gen(2005);
        long[] result = new long[2];
        XXH3.hash128(data, data.length, 0, 0, result);
        assertEquals(0x0CFABA171612493EL, result[0]);
        assertEquals(0x80DB011B9F49F18EL, result[1]);
    }
}
