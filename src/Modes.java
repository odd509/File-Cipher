import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Modes {
    protected final int BLOCK_SIZE = 64;

    protected enum Mode {
        ENCRYPT, DECRYPT
    }

    /**
     * Encrypt/decrypt an 8 byte block with DES
     * 
     * @param block  block to encrypt/decrypt
     * @param mode   encryption or decryption
     * @param rawKey the key provided as input
     * @return 8 byte cipher array
     */

    private static byte[] DES(byte[] block, Mode encOrDec, String rawKey) {

        byte[] cipherArray = {};

        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            SecretKey key = new SecretKeySpec(Utils.hash(rawKey, "SHA3-256"), 0, 8, "DES");
            if (encOrDec == Mode.ENCRYPT) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                cipherArray = cipher.doFinal(block);
            } else if (encOrDec == Mode.DECRYPT) {
                cipher.init(Cipher.DECRYPT_MODE, key);
                cipherArray = cipher.doFinal(block);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }

        return cipherArray;

    }

    /**
     * 
     * Encrypt/decrypt an 8 byte block with 2 Key Triple DES
     * The second key is provided by reversing the rawKey and concatenating it to
     * the rawKey
     * 
     * @param block    block to encrypt/decrypt
     * @param encOrDec encryption or decryption
     * @param rawKey   the key provided as input
     * @return 8 byte cipher array
     */

    private static byte[] TripleDES(byte[] block, Mode encOrDec, String rawKey) {

        byte[] cipherArray = {};

        // reverses the raw key as string to concatenate
        StringBuilder sBuilder = new StringBuilder();
        sBuilder.append(rawKey);
        sBuilder.reverse();

        String concatString = sBuilder.toString();

        if (encOrDec == Mode.ENCRYPT) {
            cipherArray = DES(DES(DES(block, Mode.ENCRYPT, rawKey), Mode.DECRYPT, rawKey.concat(concatString)),
                    Mode.ENCRYPT, rawKey);
        } else if (encOrDec == Mode.DECRYPT) {
            cipherArray = DES(DES(DES(block, Mode.DECRYPT, rawKey), Mode.ENCRYPT, rawKey.concat(concatString)),
                    Mode.DECRYPT, rawKey);
        }

        return cipherArray;

    }

    /**
     * Provides the proper cipher algorithm for encryption or decryption
     * 
     * @param algoName desired algorithm
     * @param block    block to encrypt/decrypt
     * @param encOrDec encryption or decryption
     * @param rawKey   key provided as input
     * @return 8 byte cipher array
     */

    protected static byte[] chooseAlgorithm(String algoName, byte[] block, Mode encOrDec, String rawKey) {

        byte[] cipherArray = {};
        if (algoName.equals("DES")) {

            cipherArray = DES(block, encOrDec, rawKey);
        } else if (algoName.equals("3DES")) {

            cipherArray = TripleDES(block, encOrDec, rawKey);
        }

        return cipherArray;
    }

}
