package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.util.KeyWithCertTest;
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
import java.security.cert.CertificateException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DefaultRelyingPartyRegistrationRepositoryTest {
    private static final String ENTITY_ID = "entityId";
    private static final String ENTITY_ID_ALIAS = "entityIdAlias";
    private static final String ZONE_SUBDOMAIN = "testzone";
    private static final String ZONED_ENTITY_ID = "%s.%s".formatted(ZONE_SUBDOMAIN, ENTITY_ID);
    private static final String REGISTRATION_ID = "registrationId";
    private static final String REGISTRATION_ID_2 = "registrationId2";

    private static final SamlKey samlKey1 = new SamlKey(KeyWithCertTest.encryptedKey, KeyWithCertTest.password, KeyWithCertTest.goodCert);
    private static final SamlKey samlKey2 = new SamlKey(KeyWithCertTest.ecPrivateKey, KeyWithCertTest.password, KeyWithCertTest.ecCertificate);
    private static KeyWithCert keyWithCert1;
    private static KeyWithCert keyWithCert2;

    private static final SamlConfigProps samlConfigProps = new SamlConfigProps();

    @Mock
    private IdentityZone identityZone;

    @Mock
    private IdentityZoneConfiguration identityZoneConfig;

    @Mock
    private SamlConfig samlConfig;

    private DefaultRelyingPartyRegistrationRepository repository;

    @BeforeAll
    public static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
        try {
            keyWithCert1 = KeyWithCert.fromSamlKey(samlKey1);
            keyWithCert2 = KeyWithCert.fromSamlKey(samlKey2);
        } catch (CertificateException e) {
            fail("Failed to create key with cert", e);
        }
        new IdentityZoneHolder.Initializer(null, new SamlKeyManagerFactory(samlConfigProps));
    }

    @BeforeEach
    void setUp() {
        repository = spy(new DefaultRelyingPartyRegistrationRepository(ENTITY_ID, ENTITY_ID_ALIAS));
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
                .returns(null, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("exampleEntityId", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
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
                .returns(null, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/testzone.entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/testzone.entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("exampleEntityId", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
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
                .returns(null, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/testzone.entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/testzone.entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void findByRegistrationId_NoAliasFailsOverToEntityId() {
        repository = spy(new DefaultRelyingPartyRegistrationRepository(ENTITY_ID, null));
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(ZONE_SUBDOMAIN);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID_2);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID_2, RelyingPartyRegistration::getRegistrationId)
                .returns(ZONED_ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(null, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/testzone.entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/testzone.entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void zoneWithCredentialsUsesCorrectValues() {
        samlConfigProps.setKeys(Map.of("key1", samlKey1, "key2", samlKey2));
        samlConfigProps.setActiveKeyId("key1");
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfig);
        when(identityZoneConfig.getSamlConfig()).thenReturn(samlConfig);

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration.getDecryptionX509Credentials())
                .hasSize(1)
                .first()
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(keyWithCert1.getCertificate());
        assertThat(registration.getSigningX509Credentials())
                .hasSize(2)
                .first()
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(keyWithCert1.getCertificate());
        // Check the second element
        assertThat(registration.getSigningX509Credentials())
                .element(1)
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(keyWithCert2.getCertificate());
    }
}
