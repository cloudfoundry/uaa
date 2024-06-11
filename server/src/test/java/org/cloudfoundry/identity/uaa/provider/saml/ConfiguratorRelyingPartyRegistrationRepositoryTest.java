package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ConfiguratorRelyingPartyRegistrationRepositoryTest {
    private static final String ENTITY_ID = "entityId";
    private SamlIdentityProviderConfigurator mockConfigurator;
    private KeyWithCert mockKeyWithCert;
    private ConfiguratorRelyingPartyRegistrationRepository target;
    private Function<String, String> assertionConsumerServiceLocationFunction;

    @Before
    public void setup() {
        mockConfigurator = mock(SamlIdentityProviderConfigurator.class);
        mockKeyWithCert = mock(KeyWithCert.class);
        assertionConsumerServiceLocationFunction = "{baseUrl}/saml/SSO/alias/%s"::formatted;
    }

    @Test
    public void constructor_nullConfigurator() {
        assertThrows(IllegalArgumentException.class, () -> target = new ConfiguratorRelyingPartyRegistrationRepository(true, ENTITY_ID, mockKeyWithCert, null, assertionConsumerServiceLocationFunction));
    }

    @Test
    public void testFindByRegistrationIdWhenNoneFound() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));
        target = new ConfiguratorRelyingPartyRegistrationRepository(true, ENTITY_ID, mockKeyWithCert, mockConfigurator, assertionConsumerServiceLocationFunction);

        SamlIdentityProviderDefinition mockDefinition1 = mock(SamlIdentityProviderDefinition.class);
        when(mockDefinition1.getIdpEntityAlias()).thenReturn("registration1");
        when(mockDefinition1.getNameID()).thenReturn("name1");
        when(mockDefinition1.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");

        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(List.of(mockDefinition1));
        assertNull(target.findByRegistrationId("registrationNotFound"));
    }

    @Test
    public void testFindByRegistrationId() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));
        target = new ConfiguratorRelyingPartyRegistrationRepository(true, ENTITY_ID, mockKeyWithCert, mockConfigurator, assertionConsumerServiceLocationFunction);

        //definition 1
        SamlIdentityProviderDefinition mockDefinition1 = mock(SamlIdentityProviderDefinition.class);
        when(mockDefinition1.getIdpEntityAlias()).thenReturn("registration1");
        when(mockDefinition1.getNameID()).thenReturn("name1");
        when(mockDefinition1.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");

        //definition 2
        SamlIdentityProviderDefinition mockDefinition2 = mock(SamlIdentityProviderDefinition.class);
        when(mockDefinition2.getIdpEntityAlias()).thenReturn("registration2");
        when(mockDefinition2.getNameID()).thenReturn("name2");
        when(mockDefinition2.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");

        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(mockDefinition1, mockDefinition2));
        RelyingPartyRegistration output = target.findByRegistrationId("registration1");
        assertEquals("registration1", output.getRegistrationId());
        assertEquals(ENTITY_ID, output.getEntityId());
        assertEquals("name1", output.getNameIdFormat());
    }
}