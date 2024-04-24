package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
@ConfigurationProperties(prefix="login.saml")
public class SamlKeysConfig {
    private String activeKeyId;

    private Map<String, SamlKey> keys;

    public String getActiveKeyId() {
        return activeKeyId;
    }

    public void setActiveKeyId(String activeKeyId) {
        this.activeKeyId = activeKeyId;
    }

    public Map<String, SamlKey> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, SamlKey> keys) {
        this.keys = keys;
    }

    public SamlKey getActiveSamlKey() {
        return keys.get(activeKeyId);
    }
}
