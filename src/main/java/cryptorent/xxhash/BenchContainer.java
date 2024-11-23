package cryptorent.xxhash;

public class BenchContainer {
    public enum HashId {XXH32, XXH64};
    public static long hash(HashId hashID, byte[] input, int length, int offset) {
        return switch (hashID) {
            case XXH32 -> XXHash32.hash(input, length, offset, 0);
            case XXH64 -> XXHash64.hash(input, length, offset, 0);
        };
    }
}
