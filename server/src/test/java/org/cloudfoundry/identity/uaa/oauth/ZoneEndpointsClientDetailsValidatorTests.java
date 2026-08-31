package org.cloudfoundry.identity.uaa.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.ZoneEndpointsClientDetailsValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.security.Security;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.ALLOWED_PROVIDERS;
import static org.mockito.Mockito.verify;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class ZoneEndpointsClientDetailsValidatorTests {

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

    @Mock
    private ClientSecretValidator mockClientSecretValidator;

    @org.junit.jupiter.api.BeforeAll
    static void addBouncyCastleFipsProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    private ZoneEndpointsClientDetailsValidator zoneEndpointsClientDetailsValidator;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, false);
    }

    @Test
    void createLimitedClient() {
        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "authorization_code,password", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertThat(validatedClientDetails.getClientId()).isEqualTo(clientDetails.getClientId());
        assertThat(validatedClientDetails.getScope()).hasSameElementsAs(clientDetails.getScope());
        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).hasSameElementsAs(clientDetails.getAuthorizedGrantTypes());
        assertThat(validatedClientDetails.getAuthorities()).isEqualTo(clientDetails.getAuthorities());
        assertThat(validatedClientDetails.getResourceIds()).hasSameElementsAs(Collections.singleton("none"));
        assertThat(validatedClientDetails.getAdditionalInformation()).containsEntry(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
    }

    @Test
    void createClientNoNameIsInvalid() {
        UaaClientDetails clientDetails = new UaaClientDetails("", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("secret");
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "password",
            "client_credentials",
            GRANT_TYPE_AUTHORIZATION_CODE,
            GRANT_TYPE_USER_TOKEN,
            GRANT_TYPE_REFRESH_TOKEN,
            GRANT_TYPE_SAML2_BEARER,
            GRANT_TYPE_JWT_BEARER,
            GRANT_TYPE_TOKEN_EXCHANGE
    })
    void createClientNoSecretIsInvalid(final String grantType) {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", grantType, "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("client_secret cannot be blank");
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenAdditionalInformationIsNull() {
        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource") {
            @Override
            public Map<String, Object> getAdditionalInformation() {
                return null;
            }
        };

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("client_secret cannot be blank");
    }

    @Test
    void createClientNoSecretForImplicitIsValid() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "implicit", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).hasSameElementsAs(clientDetails.getAuthorizedGrantTypes());
    }

    @Test
    void reject_invalid_grant_type() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "invalid_grant_type", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void createAdminScopeClientIsInvalid() {
        ClientDetails clientDetails = new UaaClientDetails("admin-client", null, "uaa.admin", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void createAdminAuthorityClientIsInvalid() {
        ClientDetails clientDetails = new UaaClientDetails("admin-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.admin");
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void rejectsTlsClientAuthCaWhenMtlsDisabled() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, false);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.setClientSecret("secret");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("uaa.mtls-enabled");
    }

    @Test
    void allowsTlsClientAuthCaWhenMtlsEnabled() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.setClientSecret("secret");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
        clientDetails.setAdditionalInformation(additionalInfo);

        ClientDetails validated = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);

        assertThat(validated.getAdditionalInformation())
                .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
    }

    @Test
    void allowsSecretlessClientCredentialsClientWhenTlsClientAuthCaConfigured() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatNoException().isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @Test
    void allowsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsTypedConfiguration() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(VALID_CERT, null));

        assertThatNoException().isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenTypedTlsClientAuthCaIsMalformed() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration("not-a-certificate", null));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
    }

    @Test
    void allowsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsJsonMap() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT));
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatNoException().isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @ParameterizedTest
    @MethodSource("unsupportedNestedTlsClientAuthCaValues")
    void rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaMapHasUnsupportedCaValue(Object ca) {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> tlsClientAuthConfig = new HashMap<>();
        tlsClientAuthConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, ca);
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, tlsClientAuthConfig);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
    }

    @ParameterizedTest
    @MethodSource("invalidNestedTypedTlsClientAuthConfigurations")
    void rejectsSecretlessClientCredentialsClientWhenTypedTlsClientAuthConfigurationHasUndeclaredClaimReference(
            String property, TlsClientAuthConfiguration tlsClientAuthConfig) {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        clientDetails.setTlsClientAuthConfiguration(tlsClientAuthConfig);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(property)
                .hasMessageContaining("undeclared");
    }

    @ParameterizedTest
    @MethodSource("invalidNestedMapTlsClientAuthConfigurations")
    void rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaMapHasUndeclaredClaimReference(
            String property, Map<String, Object> tlsClientAuthConfig) {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, tlsClientAuthConfig);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(property)
                .hasMessageContaining("undeclared");
    }

    @ParameterizedTest
    @MethodSource("parserNullNestedMapClaimMappings")
    void rejectsClientWithSuppliedSecretWhenNestedTlsClientAuthClaimMappingsParseToNull(
            String claimMappings, String property, Object value) {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.setClientSecret("supplied-secret");
        Map<String, Object> tlsClientAuthConfig = nestedTlsClientAuthConfig(property, value);
        tlsClientAuthConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, claimMappings);
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, tlsClientAuthConfig);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(property)
                .hasMessageContaining("undeclared");
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenTypedTlsClientAuthClaimMappingHasInvalidField() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
                VALID_CERT, Collections.singletonList(new TlsClientAuthConfiguration.ClaimMapping(null, null, "claim"))));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("invalid field");
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaJsonMapClaimMappingHasInvalidField() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> malformedClaimMapping = new HashMap<>();
        malformedClaimMapping.put("field", null);
        malformedClaimMapping.put("claim", "claim");
        Map<String, Object> tlsClientAuthConfig = new HashMap<>();
        tlsClientAuthConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
        tlsClientAuthConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                Collections.singletonList(malformedClaimMapping));
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, tlsClientAuthConfig);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("invalid field");
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenTypedTlsClientAuthCaIsBlank() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration("  ", null));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaMapIsMalformed() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, Map.of("unexpected", "value"));
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  ", "\t"})
    void rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsBlank(final String ca) {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, ca);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
    }

    @Test
    void rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsNotAString() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, 42);
        clientDetails.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
    }

    @Test
    void stillValidatesSuppliedSecretWhenTlsClientAuthCaConfigured() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, true);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.setClientSecret("supplied-secret");
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
        clientDetails.setAdditionalInformation(additionalInfo);

        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);

        verify(mockClientSecretValidator).validate("supplied-secret");
    }

    @Test
    void allowsClientWithoutMtlsFieldsWhenMtlsDisabled() {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator(mockClientSecretValidator, false);

        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "client_credentials", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        ClientDetails validated = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);

        assertThat(validated.getClientId()).isEqualTo(clientDetails.getClientId());
    }

    private static Stream<Object> unsupportedNestedTlsClientAuthCaValues() {
        return Stream.of(42, true);
    }

    private static Stream<Arguments> invalidNestedTypedTlsClientAuthConfigurations() {
        TlsClientAuthConfiguration subTemplateConfig = new TlsClientAuthConfiguration(VALID_CERT, null);
        subTemplateConfig.setSubTemplate("{undeclared}");
        TlsClientAuthConfiguration audTemplatesConfig = new TlsClientAuthConfiguration(VALID_CERT, null);
        audTemplatesConfig.setAudTemplates(Collections.singletonList("{undeclared}"));
        TlsClientAuthConfiguration requiredClaimsConfig = new TlsClientAuthConfiguration(VALID_CERT, null);
        requiredClaimsConfig.setRequiredClaims(Map.of("undeclared", "value"));
        return Stream.of(
                Arguments.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, subTemplateConfig),
                Arguments.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, audTemplatesConfig),
                Arguments.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, requiredClaimsConfig));
    }

    private static Stream<Arguments> invalidNestedMapTlsClientAuthConfigurations() {
        return Stream.of(
                Arguments.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE,
                        nestedTlsClientAuthConfig(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "{undeclared}")),
                Arguments.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                        nestedTlsClientAuthConfig(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                                Collections.singletonList("{undeclared}"))),
                Arguments.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                        nestedTlsClientAuthConfig(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                                Map.of("undeclared", "value"))));
    }

    private static Stream<Arguments> parserNullNestedMapClaimMappings() {
        return Stream.of(
                Arguments.of("", TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "{undeclared}"),
                Arguments.of("  ", TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                        Collections.singletonList("{undeclared}")),
                Arguments.of("null", TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                        Map.of("undeclared", "value")));
    }

    private static Map<String, Object> nestedTlsClientAuthConfig(String property, Object value) {
        Map<String, Object> config = new HashMap<>();
        config.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, VALID_CERT);
        config.put(property, value);
        return config;
    }
}
