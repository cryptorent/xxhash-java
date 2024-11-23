package cryptorent.xxhash;

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


            // Define the seed value for the hash function
            final int seed = 0;

            // Number of iterations to perform the hash (to get measurable time)
            final int iterations = 10;

            // Variable to accumulate hash results to prevent optimization
            long hashAccumulator = 0;

            // Perform a warm-up run to allow the JVM to optimize the code
            for (int i = 0; i < 30; i++) {
                hashAccumulator += BenchContainer.hash(hashID, data, data.length, 0);
            }

            long best = Long.MAX_VALUE;
            for (int i = 0; i < 100; i++) {
                // Record the start time in nanoseconds
                long startTime = System.nanoTime();

                // Perform the hashing multiple times
                for (int j = 0; j < iterations; j++) {
                    hashAccumulator += BenchContainer.hash(hashID, data, data.length, 0);
                }

                // Record the end time in nanoseconds
                long endTime = System.nanoTime();

                // Calculate the total time taken in nanoseconds
                long totalTime = endTime - startTime;
                if (totalTime < best)
                    best = totalTime;
            }

            // Calculate the average time per hash in nanoseconds
            double averageTimePerHash = (double) best / iterations;

            // Convert total time to milliseconds for easier readability
            double totalTimeMs = best / 1_000_000.0;
            System.out.println(hashID);
            System.out.printf("Total time for %d hashes: %.3f ms%n", iterations, totalTimeMs);
            System.out.printf("Average time per hash: %.3f ns%n", averageTimePerHash);
            System.out.println("Hash accumulator (to prevent optimization): " + hashAccumulator);
        }
    }
}
