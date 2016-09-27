package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;

public class OauthIdentityProviderDefinitionFactoryBean {
    private Map<String,AbstractXOAuthIdentityProviderDefinition> oauthIdpDefinitions = new HashMap<>();

    public OauthIdentityProviderDefinitionFactoryBean(Map<String, Map> definitions) {
        if (definitions != null) {
            for (String alias : definitions.keySet()) {
                Map idpDefinitionMap = definitions.get(alias);
                try {
                    String type = (String) idpDefinitionMap.get("type");
                    if(OAUTH20.equalsIgnoreCase(type)) {
                        RawXOAuthIdentityProviderDefinition oauthIdentityProviderDefinition = new RawXOAuthIdentityProviderDefinition();
                        oauthIdentityProviderDefinition.setCheckTokenUrl(idpDefinitionMap.get("checkTokenUrl") == null ? null : new URL((String) idpDefinitionMap.get("checkTokenUrl")));
                        setCommonProperties(idpDefinitionMap, oauthIdentityProviderDefinition);
                        oauthIdpDefinitions.put(alias, oauthIdentityProviderDefinition);
                    }
                    else if(OIDC10.equalsIgnoreCase(type)) {
                        XOIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new XOIDCIdentityProviderDefinition();
                        setCommonProperties(idpDefinitionMap, oidcIdentityProviderDefinition);
                        oidcIdentityProviderDefinition.setUserInfoUrl(idpDefinitionMap.get("userInfoUrl") == null ? null : new URL((String) idpDefinitionMap.get("userInfoUrl")));
                        oauthIdpDefinitions.put(alias, oidcIdentityProviderDefinition);
                    } else {
                        throw new IllegalArgumentException("Unknown type for provider. Type must be oauth2.0 or oidc1.0. (Was " + type + ")");
                    }
                }
                catch (MalformedURLException e) {
                    throw new IllegalArgumentException("URL is malformed.", e);
                }
            }
        }
    }

    private void setCommonProperties(Map idpDefinitionMap, AbstractXOAuthIdentityProviderDefinition idpDefinition) {
        idpDefinition.setLinkText((String)idpDefinitionMap.get("linkText"));
        idpDefinition.setRelyingPartyId((String) idpDefinitionMap.get("relyingPartyId"));
        idpDefinition.setRelyingPartySecret((String) idpDefinitionMap.get("relyingPartySecret"));
        idpDefinition.setEmailDomain((List<String>) idpDefinitionMap.get("emailDomain"));
        idpDefinition.setShowLinkText(idpDefinitionMap.get("showLinkText") == null ? true : (boolean) idpDefinitionMap.get("showLinkText"));
        idpDefinition.setAddShadowUserOnLogin(idpDefinitionMap.get("addShadowUserOnLogin") == null ? true : (boolean) idpDefinitionMap.get("addShadowUserOnLogin"));
        idpDefinition.setSkipSslValidation(idpDefinitionMap.get("skipSslValidation") == null ? false : (boolean) idpDefinitionMap.get("skipSslValidation"));
        idpDefinition.setTokenKey((String) idpDefinitionMap.get("tokenKey"));
        idpDefinition.setIssuer((String) idpDefinitionMap.get("issuer"));
        idpDefinition.setAttributeMappings((Map<String, Object>) idpDefinitionMap.get(ATTRIBUTE_MAPPINGS));
        idpDefinition.setScopes((List<String>) idpDefinitionMap.get("scopes"));
        try {
            idpDefinition.setAuthUrl(new URL((String)idpDefinitionMap.get("authUrl")));
            idpDefinition.setTokenKeyUrl(idpDefinitionMap.get("tokenKeyUrl") == null ? null : new URL((String)idpDefinitionMap.get("tokenKeyUrl")));
            idpDefinition.setTokenUrl(new URL((String)idpDefinitionMap.get("tokenUrl")));
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL is malformed.", e);
        }
    }

    public Map<String,AbstractXOAuthIdentityProviderDefinition> getOauthIdpDefinitions() {
        return oauthIdpDefinitions;
    }

    public void setOauthIdpDefinitions(Map<String,AbstractXOAuthIdentityProviderDefinition> oauthIdpDefinitions) {
        this.oauthIdpDefinitions = oauthIdpDefinitions;
    }
}
