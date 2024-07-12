package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DefaultRelyingPartyRegistrationRepositoryTest {
    private static final String ENTITY_ID = "entityId";
    private static final String ENTITY_ID_ALIAS = "entityIdAlias";
    private static final String ZONE_SUBDOMAIN = "testzone";
    private static final String ZONED_ENTITY_ID = "%s.%s".formatted(ZONE_SUBDOMAIN, ENTITY_ID);
    private static final String REGISTRATION_ID = "registrationId";
    private static final String NAME_ID = "name1";

    @Mock
    private KeyWithCert mockKeyWithCert;

    @Mock
    private IdentityZone identityZone;

    @Mock
    private IdentityZoneConfiguration identityZoneConfig;

    @Mock
    private SamlConfig samlConfig;

    private DefaultRelyingPartyRegistrationRepository repository;

    @BeforeEach
    void setUp() {
        repository = spy(new DefaultRelyingPartyRegistrationRepository(ENTITY_ID, ENTITY_ID_ALIAS, mockKeyWithCert));
    }

    @Test
    void findByRegistrationId() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));

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
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));
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
}