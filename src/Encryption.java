import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Encryption extends Modes {

    public static byte[][] CBC(byte[][] blocks, String rawKey, String IV, String algoName) {

        byte[][] cipherBlocks = new byte[blocks.length][];
        int blockCounter = 0;

        // hashing the IV and getting the first 8 bytes of it
        byte[] hashedCutIV = Arrays.copyOf(Utils.hash(IV, "SHA3-256"), 8);

        byte[] vector = new byte[8];
        byte[] cipherBlock = new byte[8];

        for (byte[] plainBlock : blocks) {

            vector = blockCounter == 0 ? hashedCutIV : cipherBlock;

            byte[] XORedArr = Utils.XORArrays(plainBlock, vector);

            cipherBlock = chooseAlgorithm(algoName, XORedArr, Mode.ENCRYPT, rawKey);
            cipherBlocks[blockCounter] = cipherBlock;
            blockCounter++;

        }

        return cipherBlocks;
    }

    public static byte[][] CFB(byte[][] blocks, String rawKey, String IV, String algoName) {

        byte[][] cipherBlocks = new byte[blocks.length][];
        int blockCounter = 0;

        // hashing the IV and getting the first 8 bytes of it
        byte[] hashedCutIV = Arrays.copyOf(Utils.hash(IV, "SHA3-256"), 8);

        byte[] vector = new byte[8];
        byte[] cipherBlock = new byte[8];

        for (byte[] plainBlock : blocks) {

            vector = blockCounter == 0 ? hashedCutIV : cipherBlock;
            cipherBlock = Utils.XORArrays(plainBlock, chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey));
            cipherBlocks[blockCounter] = cipherBlock;
            blockCounter++;
        }
        return cipherBlocks;
    }

    public static byte[][] OFB(byte[][] blocks, String rawKey, String IV, String algoName) {

        byte[][] cipherBlocks = new byte[blocks.length][];
        int blockCounter = 0;

        // hashing the IV and getting the first 8 bytes of it
        byte[] hashedCutIV = Arrays.copyOf(Utils.hash(IV, "SHA3-256"), 8);

        byte[] vector = new byte[8];
        byte[] cipherBlock = new byte[8];

        for (byte[] plainBlock : blocks) {

            vector = blockCounter == 0 ? hashedCutIV : chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey);
            cipherBlock = Utils.XORArrays(plainBlock, chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey));
            cipherBlocks[blockCounter] = cipherBlock;
            blockCounter++;
        }
        return cipherBlocks;
    }

    public static byte[][] CTR(byte[][] blocks, String rawKey, String nonce, String algoName) {

        byte[][] cipherBlocks = new byte[blocks.length][];
        int blockCounter = 0;
        byte[] vector = new byte[8];
        byte[] cipherBlock = new byte[8];

        for (byte[] plainBlock : blocks) {
            vector = Utils.concatArr(Arrays.copyOf(nonce.getBytes(), 4),
                    ByteBuffer.allocate(4).putInt(blockCounter).order(ByteOrder.LITTLE_ENDIAN).array());
            cipherBlock = Utils.XORArrays(plainBlock, chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey));
            cipherBlocks[blockCounter] = cipherBlock;
            blockCounter++;
        }

        return cipherBlocks;
    }

}
