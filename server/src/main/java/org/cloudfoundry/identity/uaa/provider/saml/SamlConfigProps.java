package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@Data
@ConfigurationProperties(prefix = "login.saml")
public class SamlConfigProps {
    private Map<String, Map<String, Object>> providers;

    private String activeKeyId;

    private Map<String, SamlKey> keys;

    private Boolean wantAssertionSigned = true;
    private Boolean signRequest = true;

    public SamlKey getActiveSamlKey() {
        return keys.get(activeKeyId);
    }
}
