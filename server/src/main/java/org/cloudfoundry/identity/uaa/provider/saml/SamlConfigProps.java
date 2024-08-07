package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.lang.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration properties for SAML
 * Loaded from the 'login.saml' section of the UAA configuration yaml file
 */
@Slf4j
@Data
@ConfigurationProperties(prefix = "login.saml")
public class SamlConfigProps {

    /**
     * Map of provider IDs to provider configuration
     */
    private Map<String, Map<String, Object>> providers;

    /**
     * Entity ID Alias to login at /saml/SSO/alias/{login.saml.entityIDAlias};
     * both SAML SP metadata and SAML Authn Request will include this as part of various SAML URLs
     * (such as the AssertionConsumerService URL);
     * if not set, UAA will fall back to login.entityID
     */
    private String entityIDAlias;

    /**
     * Default nameID if IDP nameID is not set
     * Used in SAML Authn Request:
     * <saml2p:NameIDPolicy Format="{login.saml.nameID}"/>
     */
    private String nameID;

    /**
     * Default assertionConsumerIndex if IDP value is not set
     */
    private int assertionConsumerIndex = 0;

    /**
     * The activeKeyId in the keys map
     */
    private String activeKeyId;

    /**
     * Map of key IDs to SamlKey objects
     */
    private Map<String, SamlKey> keys = new HashMap<>();

    /**
     * Local/SP metadata - want incoming assertions signed
     */
    private Boolean wantAssertionSigned = true;

    /**
     * When login.saml.signMetaData is true or not set, the SAML SP metadata has a Signature section;
     * when it's false, there is no Signature. This applies to both default and non-default zones
     */
    private Boolean signMetaData = true;

    /**
     * Local/SP metadata - requests signed
     */
    private Boolean signRequest = true;

    /**
     * Algorithm for SAML signatures.
     * Accepts: SHA1, SHA256, SHA512
     * Defaults to SHA256.
     */
    private String signatureAlgorithm = "SHA256";

    /**
     * If true, do not validate the InResponseToField part of an incoming IDP assertion (default: false)
     */
    private Boolean disableInResponseToCheck = false;

    /**
     * Get the active key
     * @return the active SamlKey, if available or null
     */
    @Nullable
    public SamlKey getActiveSamlKey() {
        return keys != null ? keys.get(activeKeyId) : null;
    }
}
