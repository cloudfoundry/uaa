package org.cloudfoundry.identity.uaa.cypto;

import java.util.HashMap;
import java.util.List;

public class ActiveEncryptionKeyService {
    private final EncryptionKey activeKeyPassphrase;

    public ActiveEncryptionKeyService(String activeKeyLabel, List<EncryptionKey> encryptionKeys) {
        activeKeyPassphrase = encryptionKeys.stream().filter(v -> v.getLabel().equals(activeKeyLabel)).findFirst().orElseGet(() -> {
            throw new NoActiveEncryptionKeyProvided(String.format("%s was not provided as an encryption key", activeKeyLabel));
        });
    }

    public String getPassphrase() {
        return this.activeKeyPassphrase.getPassphrase();
    }

    public static class EncryptionKey extends HashMap<String, String> {
        public String getLabel() {
            return this.get("label");
        }

        public String getPassphrase() {
            return this.get("passphrase");
        }
    }
}
