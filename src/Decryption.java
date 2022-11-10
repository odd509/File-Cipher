import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Decryption extends Modes {

    public static byte[][] CBC(byte[][] blocks, String rawKey, String IV, String algoName) {

        byte[][] plainBlocks = new byte[blocks.length][];
        int blockCounter = 0;

        // hashing the IV and getting the first 8 bytes of it
        byte[] hashedCutIV = Arrays.copyOf(Utils.hash(IV, "SHA3-256"), 8);

        byte[] vector = new byte[8];
        byte[] plainBlock = new byte[8];

        for (byte[] cipherBlock : blocks) {

            vector = blockCounter == 0 ? hashedCutIV : blocks[blockCounter - 1];

            byte[] cipheredBlock = chooseAlgorithm(algoName, cipherBlock, Mode.DECRYPT, rawKey);

            plainBlock = Utils.XORArrays(cipheredBlock, vector);
            plainBlocks[blockCounter] = plainBlock;
            blockCounter++;

        }

        return removePadding(plainBlocks);
    }

    public static byte[][] CFB(byte[][] blocks, String rawKey, String IV, String algoName) {

        byte[][] plainBlocks = new byte[blocks.length][];
        int blockCounter = 0;

        // hashing the IV and getting the first 8 bytes of it
        byte[] hashedCutIV = Arrays.copyOf(Utils.hash(IV, "SHA3-256"), 8);

        byte[] vector = new byte[8];
        byte[] plainBlock = new byte[8];

        for (byte[] cipherBlock : blocks) {

            vector = blockCounter == 0 ? hashedCutIV : blocks[blockCounter - 1];
            plainBlock = Utils.XORArrays(cipherBlock, chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey));
            plainBlocks[blockCounter] = plainBlock;
            blockCounter++;
        }
        return removePadding(plainBlocks);
    }

    public static byte[][] OFB(byte[][] blocks, String rawKey, String IV, String algoName) {

        byte[][] plainBlocks = new byte[blocks.length][];
        int blockCounter = 0;

        // hashing the IV and getting the first 8 bytes of it
        byte[] hashedCutIV = Arrays.copyOf(Utils.hash(IV, "SHA3-256"), 8);

        byte[] vector = new byte[8];
        byte[] plainBlock = new byte[8];

        for (byte[] cipherBlock : blocks) {

            vector = blockCounter == 0 ? hashedCutIV : chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey);
            plainBlock = Utils.XORArrays(cipherBlock, chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey));
            plainBlocks[blockCounter] = plainBlock;
            blockCounter++;
        }
        return removePadding(plainBlocks);
    }

    public static byte[][] CTR(byte[][] blocks, String rawKey, String nonce, String algoName) {

        byte[][] plainBlocks = new byte[blocks.length][];
        int blockCounter = 0;
        byte[] vector = new byte[8];
        byte[] plainBlock = new byte[8];

        for (byte[] cipherBlock : blocks) {
            vector = Utils.concatArr(Arrays.copyOf(nonce.getBytes(), 4),
                    ByteBuffer.allocate(4).putInt(blockCounter).order(ByteOrder.LITTLE_ENDIAN).array());

            plainBlock = Utils.XORArrays(cipherBlock, chooseAlgorithm(algoName, vector, Mode.ENCRYPT, rawKey));
            plainBlocks[blockCounter] = plainBlock;
            blockCounter++;
        }

        return removePadding(plainBlocks);

    }

    /**
     * Removes any padding applied to the last block
     * 
     * @param blocks padded block array
     * @return un-padded block array
     */

    private static byte[][] removePadding(byte[][] blocks) {

        byte[][] returnArr = blocks.clone();

        for (int i = 0; i < returnArr[returnArr.length - 1].length; i++) {
            if (returnArr[returnArr.length - 1][i] == (byte) 0) {
                returnArr[returnArr.length - 1] = Arrays.copyOf(returnArr[returnArr.length - 1], i);
                break;
            }
        }

        return returnArr;

    }
}
