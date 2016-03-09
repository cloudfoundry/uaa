package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.OauthIdentityProviderDefinition;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;

public class OauthIdentityProviderDefinitionFactoryBean {
    private List<OauthIdentityProviderDefinition> oauthIdpDefinitions = new ArrayList<>();

    public OauthIdentityProviderDefinitionFactoryBean(Map<String, Map> definitions) {
        if (definitions != null) {
            for (String alias : definitions.keySet()) {
                Map oauthIdpDefinitionMap = definitions.get(alias);
                OauthIdentityProviderDefinition oauthIdpDefinition = new OauthIdentityProviderDefinition();
                oauthIdpDefinition.setAlias(alias);
                oauthIdpDefinition.setLinkText((String)oauthIdpDefinitionMap.get("linkText"));
                oauthIdpDefinition.setRelyingPartyId((String)oauthIdpDefinitionMap.get("relyingPartyId"));
                oauthIdpDefinition.setRelyingPartySecret((String)oauthIdpDefinitionMap.get("relyingPartySecret"));
                oauthIdpDefinition.setShowLinkText(oauthIdpDefinitionMap.get("showLinkText") == null ? true : (boolean) oauthIdpDefinitionMap.get("showLinkText"));
                oauthIdpDefinition.setSkipSslValidation(oauthIdpDefinitionMap.get("skipSslValidation") == null ? false : (boolean) oauthIdpDefinitionMap.get("skipSslValidation"));
                oauthIdpDefinition.setTokenKey((String)oauthIdpDefinitionMap.get("tokenKey"));
                oauthIdpDefinition.setAttributeMappings((Map<String, Object>) oauthIdpDefinitionMap.get(ATTRIBUTE_MAPPINGS));
                try {
                    oauthIdpDefinition.setAuthUrl(new URL((String)oauthIdpDefinitionMap.get("authUrl")));
                    oauthIdpDefinition.setTokenKeyUrl(oauthIdpDefinitionMap.get("tokenKeyUrl") == null ? null : new URL((String)oauthIdpDefinitionMap.get("tokenKeyUrl")));
                    oauthIdpDefinition.setTokenUrl(new URL((String)oauthIdpDefinitionMap.get("tokenUrl")));
                } catch (MalformedURLException e) {
                    throw new IllegalArgumentException("URL is malformed.", e);
                }
                oauthIdpDefinitions.add(oauthIdpDefinition);
            }
        }
    }

    public List<OauthIdentityProviderDefinition> getOauthIdpDefinitions() {
        return oauthIdpDefinitions;
    }

    public void setOauthIdpDefinitions(List<OauthIdentityProviderDefinition> oauthIdpDefinitions) {
        this.oauthIdpDefinitions = oauthIdpDefinitions;
    }
}
