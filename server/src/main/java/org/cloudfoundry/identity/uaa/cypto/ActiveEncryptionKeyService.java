package org.cloudfoundry.identity.uaa.cypto;

import org.apache.directory.api.util.Strings;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class ActiveEncryptionKeyService {
    private final EncryptionKey activeKeyPassphrase;

    public ActiveEncryptionKeyService(String activeKeyLabel, List<EncryptionKey> encryptionKeys) {
        if (Strings.isEmpty(activeKeyLabel)) {
            throw new NoActiveEncryptionKeyProvided(
              "UAA cannot be started without encryption key value uaa.encryption.active_key_label"
            );
        }

        List<EncryptionKey> keysWithoutPassphrase = encryptionKeys.stream().filter(encryptionKey -> Strings.isEmpty(encryptionKey.getPassphrase())).collect(Collectors.toList());

        if (!keysWithoutPassphrase.isEmpty()) {
            throw new NoActiveEncryptionKeyProvided(
              String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[%s] is undefined",
                String.join(", ", keysWithoutPassphrase.stream().map(s -> "label=" + s.getLabel()).collect(Collectors.toList()))
              )
            );
        }

        activeKeyPassphrase =
          encryptionKeys.stream()
            .filter(v -> v.getLabel().equals(activeKeyLabel))
            .findFirst()
            .orElseGet(() -> {
                throw new NoActiveEncryptionKeyProvided(
                  String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s] is undefined", activeKeyLabel)
                );
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
