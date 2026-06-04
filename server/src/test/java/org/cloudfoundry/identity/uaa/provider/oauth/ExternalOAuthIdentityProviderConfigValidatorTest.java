package org.cloudfoundry.identity.uaa.provider.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExternalOAuthIdentityProviderConfigValidatorTest {
    private AbstractExternalOAuthIdentityProviderDefinition definition;
    private BaseIdentityProviderValidator validator;

    @BeforeEach
    void setup() throws MalformedURLException {
        definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(URI.create("http://oidc10.random-made-up-url.com/oauth/authorize").toURL());
        definition.setTokenUrl(URI.create("http://oidc10.random-made-up-url.com/oauth/token").toURL());
        definition.setTokenKeyUrl(URI.create("http://oidc10.random-made-up-url.com/token_key").toURL());
        definition.setShowLinkText(true);
        definition.setLinkText("My OIDC Provider");
        definition.setSkipSslValidation(true);
        definition.setRelyingPartyId("identity");
        definition.setRelyingPartySecret("identitysecret");
        validator = new ExternalOAuthIdentityProviderConfigValidator();
    }

    @Test
    void discovery_url_renders_other_urls_nullable() throws Exception {
        definition.setAuthUrl(null);
        definition.setTokenUrl(null);
        definition.setTokenKeyUrl(null);
        definition.setTokenKey(null);
        ((OIDCIdentityProviderDefinition) definition).setDiscoveryUrl(URI.create("http://localhost:8080/uaa/.well-known/openid-configuration").toURL());
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    void configWithNullAuthUrl_ThrowsException() {
        definition.setAuthUrl(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithNullTokenUrl_ThrowsException() {
        definition.setTokenUrl(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithNullRelyingPartyId_ThrowsException() {
        definition.setRelyingPartyId(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithNullRelyingPartySecret_ThrowsException() {
        definition.setRelyingPartySecret(null);
        definition.setAuthMethod(ClientAuthentication.CLIENT_SECRET_BASIC);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithJwtClientConfiguratButAuthMethodSecret_ThrowsException() {
        definition.setRelyingPartySecret("secret");
        ((OIDCIdentityProviderDefinition) definition).setJwtClientAuthentication(new Object());
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithPrivateKeyJwtButNoJwtConfiguration_ThrowsException() {
        definition.setAuthMethod(ClientAuthentication.PRIVATE_KEY_JWT);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithInvalidAuthMethod_ThrowsException() {
        definition.setAuthMethod("no-sure-about-this");
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithShowLinkTextTrue_mustHaveLinkText() {
        definition.setShowLinkText(true);
        definition.setLinkText(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithShowLinkTextFalse_doesNotNeedLinkText() {
        definition.setShowLinkText(false);
        definition.setLinkText(null);
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    void no_client_secret_needed_for_implicit() {
        definition.setRelyingPartySecret(null);
        definition.setResponseType("code id_token");
        validator = new ExternalOAuthIdentityProviderConfigValidator();
        validator.validate(definition);
    }

    @Test
    void configCannotBeNull() {
        assertThatThrownBy(() ->
                validator.validate((AbstractExternalOAuthIdentityProviderDefinition) null)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void tokenKeyUrl_orTokenKeyMustBeSpecified() {
        definition.setTokenKey(null);
        definition.setTokenKeyUrl(null);
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void additionalParametersAdd() {
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = (OIDCIdentityProviderDefinition) definition;
        // nothing
        oidcIdentityProviderDefinition.setAdditionalAuthzParameters(null);
        validator.validate(definition);
        // empty
        oidcIdentityProviderDefinition.setAdditionalAuthzParameters(Collections.emptyMap());
        validator.validate(definition);
        // list
        oidcIdentityProviderDefinition.setAdditionalAuthzParameters(Map.of("token_format", "jwt", "token_key", "any"));
        validator.validate(definition);
    }

    @Test
    void additionalParametersError() {
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = (OIDCIdentityProviderDefinition) definition;
        oidcIdentityProviderDefinition.setAdditionalAuthzParameters(Map.of("token_format", "jwt", "code", "1234"));
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }
}
