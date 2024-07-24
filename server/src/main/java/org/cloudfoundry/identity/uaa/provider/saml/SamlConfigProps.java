package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

@Slf4j
@Data
@ConfigurationProperties(prefix = "login.saml")
public class SamlConfigProps {
    private Map<String, Map<String, Object>> providers;

    private String activeKeyId;

    private String entityIDAlias;

    private Map<String, SamlKey> keys;

    private Boolean wantAssertionSigned = true;

    private Boolean signRequest = true;

    public SamlKey getActiveSamlKey() {
        return keys.get(activeKeyId);
    }

    public List<KeyWithCert> getKeysWithCerts() {
        return keys.values().stream().map(k -> {
            try {
                return new KeyWithCert(k);
            } catch (CertificateException e) {
                log.error("Error converting key with cert", e);
                throw new CertificateRuntimeException(e);
            }
        }).toList();
    }
}
