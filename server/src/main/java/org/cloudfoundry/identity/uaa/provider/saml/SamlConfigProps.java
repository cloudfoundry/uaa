package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.lang.Nullable;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration properties for SAML
 * Loaded from the 'login.saml' section of the UAA configuration YAML file
 */
@Slf4j
@Data
@ConfigurationProperties(prefix = "login.saml")
public class SamlConfigProps implements EnvironmentAware {

    /**
     * Map of provider IDs to provider configuration
     */
    @Setter(AccessLevel.NONE)
    private Map<String, Map<String, Object>> environmentProviders;

    /**
     * Entity ID Alias to login at /saml/SSO/alias/{login.saml.entityIDAlias};
     * both SAML SP metadata and SAML Authn Request will include this as part of various SAML URLs
     * (such as the AssertionConsumerService URL);
     * if not set, UAA will fall back to login.entityID
     */
    private String entityIDAlias;

    /**
     * Default nameID if IDP nameID is not set.
     * Defaults to urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
     * Used in SAML Authn Request:
     * <saml2p:NameIDPolicy Format="{login.saml.nameID}"/>
     */
    private String nameID = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

    /**
     * Default assertionConsumerIndex if IDP value is not set
     * Defaults to 0
     */
    private int assertionConsumerIndex;

    /**
     * The activeKeyId in the keys map
     */
    private String activeKeyId;

    /**
     * Map of key IDs to SamlKey objects
     * This replaces the deprecated settings from login.* and login.saml.*
     */
    private Map<String, SamlKey> keys = new HashMap<>();

    /**
     * Local/SP metadata - want incoming assertions signed
     * Defaults to true
     */
    private Boolean wantAssertionSigned = true;

    /**
     * When login.saml.signMetaData is true or not set, the SAML SP metadata has a Signature section;
     * when it's false, there is no Signature. This applies to both default and non-default zones.
     * Defaults to true
     */
    private Boolean signMetaData = true;

    /**
     * Local/SP metadata - requests signed
     * Defaults to true
     */
    private Boolean signRequest = true;

    /**
     * Algorithm for SAML signatures.
     * Accepts: SHA1, SHA256, SHA512
     * Defaults to SHA256.
     */
    private String signatureAlgorithm = "SHA256";

    /**
     * If true, do not validate the InResponseToField part of an incoming IDP assertion
     * Defaults to false
     */
    private Boolean disableInResponseToCheck = false;

    /**
     * Legacy setting: login.saml.serviceProviderKey
     */
    private String serviceProviderKey;

    /**
     * Legacy setting: login.saml.serviceProviderKeyPassword
     */
    private String serviceProviderKeyPassword;

    /**
     * Legacy setting: login.saml.serviceProviderCertificate
     */
    private String serviceProviderCertificate;

    /**
     * @deprecated but sill working: login.serviceProviderKey
     */
    @Deprecated(since = "77.20.0", forRemoval = true)
    private String legacyServiceProviderKey;

    /**
     * @deprecated but sill working: login.serviceProviderKeyPassword
     */
    @Deprecated(since = "77.20.0", forRemoval = true)
    private String legacyServiceProviderKeyPassword;

    /**
     * @deprecated but sill working: login.serviceProviderCertificate
     */
    @Deprecated(since = "77.20.0", forRemoval = true)
    private String legacyServiceProviderCertificate;

    /**
     * Get the active key
     *
     * @return the active SamlKey, if available or null
     */
    @Nullable
    public SamlKey getActiveSamlKey() {
        return keys != null ? keys.get(activeKeyId) : null;
    }

    /**
     * Remark: The providers map can have dots in key, typically because of domain names, e.g. cloudfoundry.org
     * With spring-boot Configuration annotations we loose the context, therefore use the map from YamlMapFactoryBean
     * from the environment.
     *
     * @param environment
     */
    @Override
    public void setEnvironment(Environment environment) {
        var nestedMap = Optional.ofNullable(((ConfigurableEnvironment) environment).getPropertySources().get("servletConfigYaml")).orElse((PropertySource) new NestedMapPropertySource("servletConfigYaml", Map.of()));
        if (nestedMap.getProperty("login.saml.providers") instanceof LinkedHashMap<?, ?> linkedHashMap) {
            this.environmentProviders = new LinkedHashMap<>((Map<String, Map<String, Object>>) linkedHashMap);
        }
        this.legacyServiceProviderKey = getNestedStringValue(nestedMap, "login.serviceProviderKey");
        this.legacyServiceProviderKeyPassword = getNestedStringValue(nestedMap, "login.serviceProviderKeyPassword");
        this.legacyServiceProviderCertificate = getNestedStringValue(nestedMap, "login.serviceProviderCertificate");
    }

    private static String getNestedStringValue(PropertySource<?> nestedMapPropertySource, String key) {
        return nestedMapPropertySource.getProperty(key) instanceof String valueString ? valueString : null;
    }
}
