package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.cypto.EncryptionService;
import org.cloudfoundry.identity.uaa.cypto.EncryptionServiceException;
import org.springframework.util.Base64Utils;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;

public class Encryptor {
    public static void main(String[] args) {
        if (args.length != 3) {
            return;
        }

        String outputFilePath = args[0];
        String passphrase = args[1];
        String plainText = args[2];
        File file = new File(outputFilePath);
        try {
            System.setOut(new PrintStream(file));

            byte[] cipherValue = new EncryptionService(passphrase).encrypt(plainText);
            String base64CipherValue = Base64Utils.encodeToString(cipherValue);
            System.out.print(base64CipherValue);
        } catch (IOException | EncryptionServiceException e) {
            e.printStackTrace();
        }
    }
}
