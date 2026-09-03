package org.cloudfoundry.identity.uaa.provider.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExternalOAuthIdentityProviderConfigValidatorTest {
    private AbstractExternalOAuthIdentityProviderDefinition definition;
    private BaseIdentityProviderValidator validator;

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

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

    // openssl req -out cert.pem -nodes -keyout private.key -newkey rsa:2048 -new -x509
    private static final String VALID_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAOpOBuLToBXJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMTcwNzE0MTcxNDE4WhcNMTcwODEzMTcxNDE4WjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA3+07F4S5Fz3wv/UFm/OWsJXm6s3pKI2mp4fSAY8rx9+0cyLAHsedWzeq
            5uKcDeRW858DOdnClaTOZC73FcvOmv1bw2eYcmfsbqHEhyR0dp+rDHt/7pr6kajC
            yUvAW+hoRRSMpooiZckxrjJ7LOa5iqRyZRwshfGN+mFSygfVguMDKrsE2rvpK6/K
            tkG/lcToLHiw4OnMnZ9ocrNRDAoCkzKGZTLJkUEr3MgOKmr2EO0P6KOAmNnOEmCf
            05ohcrUXeFZVnS5MMUzoGAOzBstZhA0dd7l297IDnWH9uIhCANCvZ9sovZWz/o3J
            pc2LyXsaI1cV7O1cGV4aEEn8zzWWGwIDAQABo1AwTjAdBgNVHQ4EFgQUXBO1+qo7
            w6iiiv1pnm+zdrQ3CzkwHwYDVR0jBBgwFoAUXBO1+qo7w6iiiv1pnm+zdrQ3Czkw
            DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAT78lT5VEIetWPGk3szPz
            CT9zNpR1F+7o3rvRTI6Psyjz4tGlyX5iU0Z99Xa9yimIEhWme2UVsgQ9uOzk2IgH
            wMbB2TTP/RRK5+eO4BUu4zWWIXsIcfC6Rqw9Y3Hki+mRpuWMv+5pcOz/H+aYeSfy
            WvVYfRZJOhcztysII4HWIxw8qqwBrf5kX8IRKZXay+A2W04A6kjjX3zfN2OzljTA
            jZbtHedUGxSHvK8x6tHEwS0lZ9eZh+V4DWyRvrunwDCtA7zJQmrJd1qbM84H/1C8
            cAC6dglvc82n1BTAZbZwWHYt+Ro3Vp0GMPsZLOXJ0g03LbkhXg4krwXjJPD42nus
            3A==
            -----END CERTIFICATE-----
            """;

    @Test
    void configWithValidCaCertificates_doesNotThrow() {
        definition.setCaCertificates(List.of(VALID_CERT));
        validator.validate(definition);
    }

    @Test
    void configWithMalformedCaCertificate_ThrowsException() {
        definition.setCaCertificates(List.of("not a pem certificate"));
        assertThatThrownBy(() ->
                validator.validate(definition)).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void configWithNullCaCertificates_doesNotThrow() {
        definition.setCaCertificates(null);
        validator.validate(definition);
    }

    @Test
    void configWithConcatenatedCaCertificateChain_doesNotThrow() {
        definition.setCaCertificates(List.of(VALID_CERT + VALID_CERT));
        validator.validate(definition);
    }
}
