import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

public class Utils {

    /**
     * Reads from the key.txt file
     * 
     * @param pathToFile the given command line argument (key.txt) taken as a String
     * @return array of Strings {IV, Key, Nonce}
     */

    public static String[] getKeyValues(String pathToFile) {

        String[] keyArr = {};
        try {
            File keyFile = new File(pathToFile);
            Scanner sc = new Scanner(keyFile);
            keyArr = sc.nextLine().split(" - ");
            sc.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return keyArr;
    }

    /**
     * Reads the plain/cipher text file
     * 
     * @param pathToFile the given command line argument (inputfile.txt) taken as a
     *                   string
     * @return the input file read into a single string
     */

    public static byte[] getText(String pathToFile) {

        File file = new File(pathToFile);
        try {
            FileInputStream fl = new FileInputStream(file);
            byte[] arr = new byte[(int) file.length()];

            fl.read(arr);

            fl.close();

            return arr;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Writes the given byte array data into the given path as bytes, used for
     * encryption results
     * 
     * @param data byte[] data
     * @param path write path
     */

    public static void output(byte[] data, String path) {
        File outputFile = new File(path);
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * Writes the given string data into the given path, used for decryption results
     * 
     * @param data string data
     * @param path write path
     */

    public static void output(String data, String path) {
        Path path1 = Paths.get(path);

        try {
            Files.writeString(path1, data, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            System.out.print("Invalid Path");
        }

    }

    /**
     * 
     * Logs to run.log
     * 
     * @param inputFileName
     * @param outputFileName
     * @param encOrDec
     * @param algorithm
     * @param mode
     * @param elapsedTimeMs
     */

    public static void log(String inputFileName, String outputFileName, String encOrDec, String algorithm, String mode,
            long elapsedTimeMs) {

        File file = new File("run.log");
        try (FileWriter fr = new FileWriter(file, true)) {

            fr.write(inputFileName + " " + outputFileName + " " + encOrDec + " " + algorithm + " " + mode + " "
                    + elapsedTimeMs + "\n");
            fr.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * Hashes the given string with the given algorithm, returns the hash as a byte
     * array
     * 
     * @param s         string to be hashed
     * @param algorithm desired hash algorithm (MD4 - MD5 - SHA-256 etc.)
     * @return
     */

    public static byte[] hash(String s, String algorithm) {
        MessageDigest md;
        byte[] hashedBytes = {};

        try {
            md = MessageDigest.getInstance(algorithm);
            byte[] messageDigest = md.digest(s.getBytes("UTF-8"));

            BigInteger bigInt = new BigInteger(1, messageDigest);
            String hashString = bigInt.toString(16);
            hashedBytes = hashString.getBytes("UTF-8");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return hashedBytes;
    }

    /**
     * Divides the provided string into an array of 8 byte arrays and pads the last
     * array with zeroes (0) until it is 8 bytes
     * 
     * @param plainText provided string
     * @return divided and padded array of 8 byte arrays
     * @throws UnsupportedEncodingException
     */

    public static byte[][] divideAndPad(byte[] inputByteArr) {

        // dividing into blocks of 8 byte arrays
        final int length = inputByteArr.length;
        final byte[][] blockArr = new byte[(length + 8 - 1) / 8][];
        int destIndex = 0;
        int stopIndex = 0;

        for (int startIndex = 0; startIndex + 8 <= length; startIndex += 8) {
            stopIndex += 8;
            blockArr[destIndex++] = Arrays.copyOfRange(inputByteArr, startIndex, stopIndex);
        }

        if (stopIndex < length)
            blockArr[destIndex] = Arrays.copyOfRange(inputByteArr, stopIndex, length);

        // padding
        if (blockArr[blockArr.length - 1].length != 8) {
            blockArr[blockArr.length - 1] = Arrays.copyOf(blockArr[destIndex], 8);
        }
        return blockArr;
    }

    /**
     * XORs two 8-byte arrays
     * 
     * @param arr1 first 8-byte array
     * @param arr2 second 8-byte array
     * @return output
     */

    public static byte[] XORArrays(byte[] arr1, byte[] arr2) {

        if (arr1.length != arr2.length) {
            return null;
        }

        byte[] returnArr = new byte[8];

        for (int i = 0; i < arr2.length; i++) {
            returnArr[i] = (byte) (arr1[i] ^ arr2[i]);
        }

        return returnArr;

    }

    /**
     * Merge block arrays to a single 1D byte array
     * 
     * @param arr blocks
     * @return merged 1D array
     */

    public static byte[] blocksToArr(byte[][] arr) {
        byte[] returnArr = new byte[(arr.length - 1) * 8 + (arr[arr.length - 1].length)];

        int counter = 0;
        for (byte[] bArr : arr) {
            for (int i = 0; i < bArr.length; i++) {
                returnArr[counter] = bArr[i];
                counter++;
            }
        }
        return returnArr;
    }

    /**
     * Concatenates two arrays
     * 
     * @param arr1
     * @param arr2
     * @return
     */

    public static byte[] concatArr(byte[] arr1, byte[] arr2) {
        byte[] c = new byte[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, c, 0, arr1.length);
        System.arraycopy(arr2, 0, c, arr1.length, arr2.length);

        return c;
    }

    /**
     * Process the given input
     * 
     * @param plainText text to encrypt or decrypt
     * @param keyArr    IV - Key - Nonce array
     * @param encOrDec  "-e" or "-d"
     * @param algoName  "DES" or "3DES"
     * @param mode      "CBC" or "CFB" or "OFB" or "CTR"
     */

    public static void processInputs(byte[] inputByteArr, String[] keyArr, String encOrDec, String algoName,
            String mode, String outputPath) {
        String IV = keyArr[0];
        String key = keyArr[1];
        String nonce = keyArr[2];
        byte[][] blocks = Utils.divideAndPad(inputByteArr);

        if (encOrDec.equals("-e")) {
            switch (mode) {
                case "CBC":
                    Utils.output(Utils.blocksToArr(Encryption.CBC(blocks, key, IV, algoName)), outputPath);
                    break;

                case "CFB":
                    Utils.output(Utils.blocksToArr(Encryption.CFB(blocks, key, IV, algoName)), outputPath);
                    break;

                case "OFB":
                    Utils.output(Utils.blocksToArr(Encryption.OFB(blocks, key, IV, algoName)), outputPath);
                    break;

                case "CTR":
                    Utils.output(Utils.blocksToArr(Encryption.CTR(blocks, key, nonce, algoName)), outputPath);
                    break;

                default:
                    break;
            }
        } else if (encOrDec.equals("-d")) {
            switch (mode) {
                case "CBC":
                    Utils.output((new String(Utils.blocksToArr(Decryption.CBC(blocks, key, IV, algoName)),
                            StandardCharsets.UTF_8)), outputPath);
                    break;
                case "CFB":
                    Utils.output((new String(Utils.blocksToArr(Decryption.CFB(blocks, key, IV, algoName)),
                            StandardCharsets.UTF_8)), outputPath);
                    break;

                case "OFB":
                    Utils.output((new String(Utils.blocksToArr(Decryption.OFB(blocks, key, IV, algoName)),
                            StandardCharsets.UTF_8)), outputPath);
                    break;

                case "CTR":
                    Utils.output((new String(Utils.blocksToArr(Decryption.CTR(blocks, key, nonce, algoName)),
                            StandardCharsets.UTF_8)), outputPath);
                    break;

                default:
                    break;
            }
        } else {
            System.out.println("Invalid input. Try -e or -d");
        }

    }

    /**
     * for FileCipher -h command. Gives information about command line arguments
     * 
     */

    public static void printHelp() {
        System.out.println(
                "The program must be executed by command line arguments. The arguments are listed below;\n\n" +
                        "FileCipher -e -i inputFile -o outFile algorithm mode key-file\n" +
                        "* -e or -d denotes encryption and decryption. To encrypt input use -e, to decrypt the input use -d.\n"
                        +
                        "* -i inputFile denotes the name/path of the input file.\n" +
                        "* -o outFile denotes the name/path of the output file.\n" +
                        "* algorithm denotes the name of the encryption/decryption algorithm, which can be DES or 3DES.\n"
                        +
                        "* mode denotes the mode of the encryption/decryption algorithm, which can be CBC, CFB, OFB, or CTR.\n"
                        +
                        "* key f ile denotes the name/path of the file that contains the initialization vector,key, and nonce values.");
    }

}
