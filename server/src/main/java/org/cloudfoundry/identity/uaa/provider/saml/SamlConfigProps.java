package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Data
@ConfigurationProperties(prefix = "login.saml")
public class SamlConfigProps {
    private Map<String, Map<String, Object>> providers;

    private String activeKeyId;

    private String entityIDAlias;

    /**
     * Algorithm for SAML signatures.
     * Accepts: SHA1, SHA256, SHA512
     * Defaults to SHA256.
     */
    private String signatureAlgorithm = "SHA256";

    private Map<String, SamlKey> keys = new HashMap<>();

    private Boolean wantAssertionSigned = true;

    private Boolean signRequest = true;

    private Boolean disableInResponseToCheck = false;

    /**
     * When login.saml.signMetaData is true or not set, the SAML SP metadata has a Signature section;
     * when it's false, there is no Signature. This applies to both default and non-default zones
     */
    private Boolean signMetaData = true;

    public SamlKey getActiveSamlKey() {
        return keys != null ? keys.get(activeKeyId) : null;
    }
}
