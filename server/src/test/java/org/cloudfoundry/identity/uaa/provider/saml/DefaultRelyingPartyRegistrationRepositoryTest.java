package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.security.Security;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.x509Certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.x509Certificate2;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;

@ExtendWith(MockitoExtension.class)
class DefaultRelyingPartyRegistrationRepositoryTest {
    private static final String ENTITY_ID = "entityId";
    private static final String ENTITY_ID_ALIAS = "entityIdAlias";
    private static final String NAME_ID_FORMAT = "nameIdFormat";
    private static final String ZONE_SUBDOMAIN = "testzone";
    private static final String ZONED_ENTITY_ID = "%s.%s".formatted(ZONE_SUBDOMAIN, ENTITY_ID);
    private static final String REGISTRATION_ID = "registrationId";
    private static final String REGISTRATION_ID_2 = "registrationId2";

    private static final SamlConfigProps samlConfigProps = Saml2TestUtils.createTestSamlProperties();

    @Mock
    private IdentityZone identityZone;

    @Mock
    private IdentityZoneConfiguration identityZoneConfig;

    @Mock
    private SamlConfig samlConfig;

    private DefaultRelyingPartyRegistrationRepository repository;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
        new IdentityZoneHolder.Initializer(null, new SamlKeyManagerFactory(samlConfigProps));
    }

    @BeforeEach
    void beforeEach() {
        repository = spy(new DefaultRelyingPartyRegistrationRepository(ENTITY_ID, ENTITY_ID_ALIAS, List.of(), NAME_ID_FORMAT));
    }

    @Test
    void findByRegistrationId() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfig);
        when(identityZoneConfig.getSamlConfig()).thenReturn(samlConfig);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID_FORMAT, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("entityId", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void findByRegistrationIdForZone() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getConfig()).thenReturn(identityZoneConfig);
        when(identityZone.getSubdomain()).thenReturn(ZONE_SUBDOMAIN);
        when(identityZoneConfig.getSamlConfig()).thenReturn(samlConfig);
        when(samlConfig.getEntityID()).thenReturn(ZONED_ENTITY_ID);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ZONED_ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID_FORMAT, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/testzone.entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/testzone.entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("testzone.entityId", RelyingPartyRegistration.AssertingPartyDetails::getEntityId)
                // signature algorithm defaults to SHA256
                .extracting(RelyingPartyRegistration.AssertingPartyDetails::getSigningAlgorithms)
                .isEqualTo(List.of(ALGO_ID_SIGNATURE_RSA_SHA256));
    }

    @Test
    void findByRegistrationIdForZoneWithoutConfig() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(ZONE_SUBDOMAIN);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID_2);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID_2, RelyingPartyRegistration::getRegistrationId)
                .returns(ZONED_ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID_FORMAT, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/testzone.entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/testzone.entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void findByRegistrationIdForZoneWithoutConfig_WhenUaaWideSamlEntityIdIsInUrlFormat() {
        String uaaWideEntityIDInUrlFormat = "https://login.foo.cf-app.com";
        repository = spy(new DefaultRelyingPartyRegistrationRepository(uaaWideEntityIDInUrlFormat, uaaWideEntityIDInUrlFormat, List.of(), NAME_ID_FORMAT));

        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(ZONE_SUBDOMAIN);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID_2);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID_2, RelyingPartyRegistration::getRegistrationId)
                .returns("https://%s.login.foo.cf-app.com".formatted(ZONE_SUBDOMAIN), RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID_FORMAT, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/%s.login.foo.cf-app.com".formatted(ZONE_SUBDOMAIN), RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/%s.login.foo.cf-app.com".formatted(ZONE_SUBDOMAIN), RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void findByRegistrationId_NoAliasFailsOverToEntityId() {
        repository = spy(new DefaultRelyingPartyRegistrationRepository(ENTITY_ID, null, List.of(), NAME_ID_FORMAT));
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfig);
        when(identityZoneConfig.getSamlConfig()).thenReturn(samlConfig);
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(ZONE_SUBDOMAIN);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID_2);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID_2, RelyingPartyRegistration::getRegistrationId)
                .returns(ZONED_ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID_FORMAT, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/testzone.entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/testzone.entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void zoneWithCredentialsUsesCorrectValues() {
        samlConfigProps.setKeys(Map.of(keyName1(), samlKey1(), keyName2(), samlKey2()));
        samlConfigProps.setActiveKeyId(keyName1());
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfig);
        when(identityZoneConfig.getSamlConfig()).thenReturn(samlConfig);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration.getDecryptionX509Credentials())
                .hasSize(1)
                .first()
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(x509Certificate1());
        assertThat(registration.getSigningX509Credentials())
                .hasSize(2)
                .first()
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(x509Certificate1());
        // Check the second element
        assertThat(registration.getSigningX509Credentials())
                .element(1)
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(x509Certificate2());
    }

    @Test
    void withSha512SignatureAlgorithm() {
        repository = spy(new DefaultRelyingPartyRegistrationRepository(ENTITY_ID, ENTITY_ID_ALIAS, List.of(SignatureAlgorithm.SHA512), NAME_ID_FORMAT));
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfig);
        when(identityZoneConfig.getSamlConfig()).thenReturn(samlConfig);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration.getAssertingPartyDetails().getSigningAlgorithms())
                .hasSize(1)
                .first()
                .isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA512);
    }
}
