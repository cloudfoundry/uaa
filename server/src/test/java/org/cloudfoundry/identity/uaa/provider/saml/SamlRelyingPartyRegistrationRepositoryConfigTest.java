package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCertTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import java.security.Security;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SamlRelyingPartyRegistrationRepositoryConfigTest {
    private static final String KEY = KeyWithCertTest.encryptedKey;
    private static final String PASSPHRASE = KeyWithCertTest.password;
    private static final String CERT = KeyWithCertTest.goodCert;
    private static final String ENTITY_ID = "entityId";
    private static final String NAME_ID = "nameIdFormat";
    private static final boolean SIGN_REQUEST = true;

    @Mock
    SamlConfigProps samlConfigProps;

    @Mock
    BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData;

    @Mock
    SamlIdentityProviderConfigurator samlIdentityProviderConfigurator;

    @Mock
    SamlKey activeSamlKey;

    @BeforeAll
    public static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    public void setup() {
        when(samlConfigProps.getActiveSamlKey()).thenReturn(activeSamlKey);
        when(activeSamlKey.getKey()).thenReturn(KEY);
        when(activeSamlKey.getPassphrase()).thenReturn(PASSPHRASE);
        when(activeSamlKey.getCertificate()).thenReturn(CERT);
    }

    @Test
    void relyingPartyRegistrationRepository() throws CertificateException {
        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID, samlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, SIGN_REQUEST);
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);
        assertThat(repository).isNotNull();
    }

    @Test
    void relyingPartyRegistrationResolver() throws CertificateException {
        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID, samlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, SIGN_REQUEST);
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);
        RelyingPartyRegistrationResolver resolver = config.relyingPartyRegistrationResolver(repository);

        assertThat(resolver).isNotNull();
    }

    @Test
    void buildsRegistrationForExample() throws CertificateException {
        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID, samlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, SIGN_REQUEST);
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);
        RelyingPartyRegistration registration = repository.findByRegistrationId("example");
        assertThat(registration)
                .returns("example", RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("exampleEntityId", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }
}
