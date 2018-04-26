package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.cypto.EncryptionService;
import org.cloudfoundry.identity.uaa.cypto.EncryptionServiceException;
import org.springframework.util.Base64Utils;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;

public class Decryptor {
    public static void main(String[] args) {
        if (args.length != 3) {
            return;
        }

        String outputFilePath = args[0];
        String passphrase = args[1];
        String cipherValue = args[2];
        File file = new File(outputFilePath);
        try {
            System.setOut(new PrintStream(file));

            byte[] base64DecodedCipherValue = Base64Utils.decodeFromString(cipherValue);
            byte[] decryptedValue = new EncryptionService(passphrase).decrypt(base64DecodedCipherValue);
            System.out.println(new String(decryptedValue));
        } catch (IOException | EncryptionServiceException e) {
            e.printStackTrace();
        }
    }
}
