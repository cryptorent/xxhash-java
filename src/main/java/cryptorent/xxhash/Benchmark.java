package cryptorent.xxhash;

import java.util.Map;
import java.util.TreeMap;

public class Benchmark {
    public static void run() {
        // Define the size of the byte array (e.g., 10 MB)
        final int size = 10 * 1024 * 1024; // 10 megabytes

        // Initialize the byte array with repeating values from 0 to 255
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i % 256);
        }

        for (BenchContainer.HashId hashID : BenchContainer.HashId.values()) {
            //trick, because time is musual too long for smallest or largest chunk size
            int[] chunkSizes = { 5,size, 10,size, 20,size, 40,size, 200,size, 1000};
            Map<Integer,Long> best = new TreeMap<>();
            for (int chunkSize: chunkSizes) {
                best.put(chunkSize,Long.MAX_VALUE);
            }
            long hashAccumulator = 0;
            for (int i = 0; i < 10; i++) {
                for (int chunkSize : chunkSizes) {
                    long startTime = System.nanoTime();
                    int offset = 0;
                    while (offset + chunkSize <= data.length) {
                        hashAccumulator += BenchContainer.hash(hashID, data, chunkSize, offset);
                        offset += chunkSize;
                    }
                    long endTime = System.nanoTime();
                    long totalTime = endTime - startTime;
                    if (totalTime < best.get(chunkSize))
                        best.replace(chunkSize, totalTime);
                }
            }
            System.out.println("Hash accumulator (to prevent optimization): " + hashAccumulator);
            System.out.println(hashID);
            for (int chunkSize: best.keySet()) {
                double totalTimeMs = best.get(chunkSize) / 1_000_000.0;
                System.out.printf("chunk size = %d best time %.3f ms%n", chunkSize, totalTimeMs);
            }
        }
    }
}
