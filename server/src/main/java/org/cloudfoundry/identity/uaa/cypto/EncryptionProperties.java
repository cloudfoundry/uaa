package org.cloudfoundry.identity.uaa.cypto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "encryption")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EncryptionProperties {

    private String activeKeyLabel;
    private List<EncryptionKeyService.EncryptionKey> encryptionKeys;

}
