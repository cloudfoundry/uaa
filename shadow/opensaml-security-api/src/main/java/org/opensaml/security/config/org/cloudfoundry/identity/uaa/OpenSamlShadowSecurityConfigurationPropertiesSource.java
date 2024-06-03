package org.opensaml.security.config.org.cloudfoundry.identity.uaa;

import org.opensaml.core.config.ConfigurationPropertiesSource;

import java.util.Properties;

public class OpenSamlShadowSecurityConfigurationPropertiesSource implements ConfigurationPropertiesSource {

    @Override
    public Properties getProperties() {
        Properties properties = new Properties();
        properties.setProperty("opensaml.config.ecdh.defaultKDF", "PBKDF2");
        return properties;
    }
}