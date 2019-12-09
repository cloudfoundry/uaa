package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;

public class XOAuthIdentityProviderConfigValidatorTest {
    private AbstractXOAuthIdentityProviderDefinition definition;
    private BaseIdentityProviderValidator validator;

    @Before
    public void setup() throws MalformedURLException {
        definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("http://oidc10.random-made-up-url.com/oauth/authorize"));
        definition.setTokenUrl(new URL("http://oidc10.random-made-up-url.com/oauth/token"));
        definition.setTokenKeyUrl(new URL("http://oidc10.random-made-up-url.com/token_key"));
        definition.setShowLinkText(true);
        definition.setLinkText("My OIDC Provider");
        definition.setSkipSslValidation(true);
        definition.setRelyingPartyId("identity");
        definition.setRelyingPartySecret("identitysecret");
        validator = new XOAuthIdentityProviderConfigValidator();
    }

    @Test
    public void discovery_url_renders_other_urls_nullable() throws Exception {
        definition.setAuthUrl(null);
        definition.setTokenUrl(null);
        definition.setTokenKeyUrl(null);
        definition.setTokenKey(null);
        ((OIDCIdentityProviderDefinition)definition).setDiscoveryUrl(new URL("http://localhost:8080/uaa/.well-known/openid-configuration"));
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullAuthUrl_ThrowsException() {
        definition.setAuthUrl(null);
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullTokenUrl_ThrowsException() {
        definition.setTokenUrl(null);
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullRelyingPartyId_ThrowsException() {
        definition.setRelyingPartyId(null);
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullRelyingPartySecret_ThrowsException() {
        definition.setRelyingPartySecret(null);
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithShowLinkTextTrue_mustHaveLinkText() {
        definition.setShowLinkText(true);
        definition.setLinkText(null);
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    public void configWithShowLinkTextFalse_doesNotNeedLinkText() {
        definition.setShowLinkText(false);
        definition.setLinkText(null);
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    public void no_client_secret_needed_for_implicit() {
        definition.setRelyingPartySecret(null);
        definition.setResponseType("code id_token");
        validator = new XOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }


    @Test(expected = IllegalArgumentException.class)
    public void configCannotBeNull() {
        validator.validate((AbstractXOAuthIdentityProviderDefinition)null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tokenKeyUrl_orTokenKeyMustBeSpecified() {
        definition.setTokenKey(null);
        definition.setTokenKeyUrl(null);
        validator.validate(definition);
    }
}
