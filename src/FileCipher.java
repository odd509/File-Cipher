public class FileCipher {
    public static void main(String[] args) throws Exception {

        long startTime = System.currentTimeMillis();

        if (args.length == 1 && args[0].equals("-h")) {
            Utils.printHelp();
            System.exit(0);
        } else if (args.length < 8) {
            System.out.println("Invalid input size");
            System.exit(0);
        }

        // get inputs 0 1 2 3 4 5 6 7
        // input format: FileCipher −e −i inputFile −o outFile algorithm mode keyFile
        String[] keyArr = Utils.getKeyValues(args[7]); // IV - Key - Nonce

        byte[] inputByteArr = Utils.getText(args[2]);

        // process inputs

        Utils.processInputs(inputByteArr, keyArr, args[0], args[5], args[6], args[4]);

        long endTime = System.currentTimeMillis();

        Utils.log(args[2], args[4], args[0].equals("-e") ? "enc" : "dec", args[5],
                args[6], endTime - startTime);

    }

}
