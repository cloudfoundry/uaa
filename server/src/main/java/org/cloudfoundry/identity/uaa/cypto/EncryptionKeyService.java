package org.cloudfoundry.identity.uaa.cypto;

import org.apache.directory.api.util.Strings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

@Service("activeKeyService")
public class EncryptionKeyService {

    private final EncryptionProperties encryptionProperties;

    private EncryptionKey activeKey;

    public EncryptionKeyService(EncryptionProperties encryptionProperties) {
        this.encryptionProperties = encryptionProperties;
    }

    @PostConstruct
    public void postConstruct() {
        String activeKeyLabel = encryptionProperties.getActiveKeyLabel();
        List<EncryptionKey> encryptionKeys = encryptionProperties.getEncryptionKeys();

        if (Strings.isEmpty(activeKeyLabel)) {
            throw new NoActiveEncryptionKeyProvided(
              "UAA cannot be started without encryption key value uaa.encryption.active_key_label"
            );
        }

        List<EncryptionKey> keysWithoutPassphrase = encryptionKeys.stream()
                .filter(encryptionKey -> Strings.isEmpty(encryptionKey.getPassphrase())).collect(Collectors.toList());
        if (!keysWithoutPassphrase.isEmpty()) {
            throw new NoActiveEncryptionKeyProvided(
              String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[%s] is undefined",
                String.join(", ", keysWithoutPassphrase.stream().map(s -> "label=" + s.getLabel()).collect(Collectors.toList()))
              )
            );
        }

        List<EncryptionKey> invalidLengthKeys = encryptionKeys.stream()
                .filter(encryptionKey -> encryptionKey.getPassphrase().length() < 8).collect(Collectors.toList());
        if (!invalidLengthKeys.isEmpty()) {
            throw new NoActiveEncryptionKeyProvided(
              String.format("The required length of the encryption passphrases for [%s] need to be at least 8 characters long.",
                String.join(", ", invalidLengthKeys.stream().map(s -> "label=" + s.getLabel()).collect(Collectors.toList()))
              )
            );
        }

        Set<String> keyCount = new HashSet<>();
        List<String> duplicateKeyLabels = new ArrayList<>();
        for (EncryptionKey encryptionKey : encryptionKeys) {
            if (keyCount.contains(encryptionKey.getLabel())) {
                duplicateKeyLabels.add(encryptionKey.getLabel());
            } else {
                keyCount.add(encryptionKey.getLabel());
            }
        }
        if (!duplicateKeyLabels.isEmpty()) {
            throw new NoActiveEncryptionKeyProvided(
              String.format("UAA cannot be started as multiple keys have the same label in uaa.encryption.encryption_keys/[%s]",
                String.join(", ", duplicateKeyLabels.stream().map(s -> "label=" + s).collect(Collectors.toList()))
              )
            );
        }

        activeKey =
          encryptionKeys.stream()
            .filter(v -> v.getLabel().equals(activeKeyLabel))
            .findFirst()
            .orElseGet(() -> {
                throw new NoActiveEncryptionKeyProvided(
                  String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s] is undefined", activeKeyLabel)
                );
            });
    }

    public EncryptionKey getActiveKey() {
        return this.activeKey;
    }

    public Optional<EncryptionKey> getKey(String keyLabel) {
        for (EncryptionKey key : encryptionProperties.getEncryptionKeys()) {
            if (key.getLabel().equals(keyLabel)) {
                return Optional.of(key);
            }
        }
        return Optional.empty();
    }

}
