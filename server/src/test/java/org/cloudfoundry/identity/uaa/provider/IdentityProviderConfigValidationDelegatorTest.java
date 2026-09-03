package org.cloudfoundry.identity.uaa.provider;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.ldap.LdapIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.uaa.UaaIdentityProviderConfigValidator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Security;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IdentityProviderConfigValidationDelegatorTest {

    @Mock
    private UaaIdentityProviderConfigValidator mockUaaIdentityProviderConfigValidator;

    @Mock
    private LdapIdentityProviderConfigValidator mockLdapIdentityProviderConfigValidator;

    @Mock
    private ExternalOAuthIdentityProviderConfigValidator mockExternalOAuthIdentityProviderConfigValidator;

    @InjectMocks
    private IdentityProviderConfigValidationDelegator identityProviderConfigValidationDelegator;

    private IdentityProvider<AbstractIdentityProviderDefinition> identityProvider;

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void setup() {
        identityProvider = new IdentityProvider<>();
    }

    @Test
    void null_identity_provider() {
        assertThatThrownBy(() -> identityProviderConfigValidationDelegator.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Provider cannot be null");
    }

    @Test
    void uaa_validator_with_nodefinition_is_invoked() {
        identityProvider.setType(UAA);

        identityProviderConfigValidationDelegator.validate(identityProvider);

        verify(mockUaaIdentityProviderConfigValidator).validate(identityProvider);
        verifyNoInteractions(mockLdapIdentityProviderConfigValidator);
        verifyNoInteractions(mockExternalOAuthIdentityProviderConfigValidator);
    }

    @Test
    void ldap_validator_with_definition_is_invoked() {
        identityProvider.setType(LDAP);

        identityProviderConfigValidationDelegator.validate(identityProvider);

        verifyNoInteractions(mockUaaIdentityProviderConfigValidator);
        verify(mockLdapIdentityProviderConfigValidator).validate(identityProvider);
        verifyNoInteractions(mockExternalOAuthIdentityProviderConfigValidator);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            OAUTH20,
            OIDC10
    })
    void externalOAuth_validator_with_definition_is_invoked(final String type) {
        identityProvider.setType(type);

        identityProviderConfigValidationDelegator.validate(identityProvider);

        verifyNoInteractions(mockUaaIdentityProviderConfigValidator);
        verifyNoInteractions(mockLdapIdentityProviderConfigValidator);
        verify(mockExternalOAuthIdentityProviderConfigValidator).validate(identityProvider);
    }

    @ParameterizedTest(name = "invalid provider with type {0} and origin ldap")
    @ValueSource(strings = {
            OAUTH20,
            OIDC10,
            SAML
    })
    void external_validator_with_reserved_type_ldap(final String type) {
        identityProvider.setType(type);
        identityProvider.setOriginKey(LDAP);

        assertThatThrownBy(() -> identityProviderConfigValidationDelegator.validate(identityProvider))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Origin \"ldap\" not allowed for type \"" + type + "\"");
    }

    @ParameterizedTest(name = "invalid provider with type {0} and origin uaa")
    @ValueSource(strings = {
            OAUTH20,
            OIDC10,
            SAML
    })
    void external_validator_with_reserved_type_uaa(final String type) {
        identityProvider.setType(type);
        identityProvider.setOriginKey(UAA);

        assertThatThrownBy(() -> identityProviderConfigValidationDelegator.validate(identityProvider))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Origin \"uaa\" not allowed for type \"" + type + "\"");
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
    void saml_withValidCaCertificates_doesNotThrow() {
        identityProvider.setType(SAML);
        identityProvider.setOriginKey("my-saml-idp");
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setCaCertificates(List.of(VALID_CERT));
        identityProvider.setConfig(definition);

        assertThatCode(() -> identityProviderConfigValidationDelegator.validate(identityProvider)).doesNotThrowAnyException();
    }

    @Test
    void saml_withMalformedCaCertificate_throws() {
        identityProvider.setType(SAML);
        identityProvider.setOriginKey("my-saml-idp");
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setCaCertificates(List.of("not a pem certificate"));
        identityProvider.setConfig(definition);

        assertThatThrownBy(() -> identityProviderConfigValidationDelegator.validate(identityProvider))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void saml_withNoCaCertificates_doesNotThrow() {
        identityProvider.setType(SAML);
        identityProvider.setOriginKey("my-saml-idp");
        identityProvider.setConfig(new SamlIdentityProviderDefinition());

        assertThatCode(() -> identityProviderConfigValidationDelegator.validate(identityProvider)).doesNotThrowAnyException();
    }

    @Test
    void saml_withConcatenatedCaCertificateChain_doesNotThrow() {
        identityProvider.setType(SAML);
        identityProvider.setOriginKey("my-saml-idp");
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setCaCertificates(List.of(VALID_CERT + VALID_CERT));
        identityProvider.setConfig(definition);

        assertThatCode(() -> identityProviderConfigValidationDelegator.validate(identityProvider)).doesNotThrowAnyException();
    }
}
