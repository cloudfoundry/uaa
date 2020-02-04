package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;

public class ExternalOAuthIdentityProviderConfigValidatorTest {
    private AbstractExternalOAuthIdentityProviderDefinition definition;
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
        validator = new ExternalOAuthIdentityProviderConfigValidator();
    }

    @Test
    public void discovery_url_renders_other_urls_nullable() throws Exception {
        definition.setAuthUrl(null);
        definition.setTokenUrl(null);
        definition.setTokenKeyUrl(null);
        definition.setTokenKey(null);
        ((OIDCIdentityProviderDefinition)definition).setDiscoveryUrl(new URL("http://localhost:8080/uaa/.well-known/openid-configuration"));
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullAuthUrl_ThrowsException() {
        definition.setAuthUrl(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullTokenUrl_ThrowsException() {
        definition.setTokenUrl(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullRelyingPartyId_ThrowsException() {
        definition.setRelyingPartyId(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithNullRelyingPartySecret_ThrowsException() {
        definition.setRelyingPartySecret(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test(expected = IllegalArgumentException.class)
    public void configWithShowLinkTextTrue_mustHaveLinkText() {
        definition.setShowLinkText(true);
        definition.setLinkText(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    public void configWithShowLinkTextFalse_doesNotNeedLinkText() {
        definition.setShowLinkText(false);
        definition.setLinkText(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    public void no_client_secret_needed_for_implicit() {
        definition.setRelyingPartySecret(null);
        definition.setResponseType("code id_token");
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }


    @Test(expected = IllegalArgumentException.class)
    public void configCannotBeNull() {
        validator.validate((AbstractExternalOAuthIdentityProviderDefinition)null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tokenKeyUrl_orTokenKeyMustBeSpecified() {
        definition.setTokenKey(null);
        definition.setTokenKeyUrl(null);
        validator.validate(definition);
    }
}
