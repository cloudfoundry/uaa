package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class MfaProviderEndpointsTest {

    MfaProviderEndpoints endpoint = new MfaProviderEndpoints();
    MfaProviderProvisioning provisioning;
    MfaProviderValidator validator;

    @Before
    public void setup() {

        provisioning = mock(JdbcMfaProviderProvisioning.class);
        validator = mock(GeneralMfaProviderValidator.class);
        endpoint.setMfaProviderProvisioning(provisioning);
        endpoint.setMfaProviderValidator(validator);
    }

    @Test
    public void testCreateDefaultIssuer() {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        Mockito.when(provisioning.create(Mockito.any(), Mockito.anyString())).thenReturn(mfaProvider);


        ResponseEntity<MfaProvider> mfaProviderResponseEntity = endpoint.createMfaProvider(mfaProvider);
        assertEquals(IdentityZoneHolder.get().getName(), mfaProviderResponseEntity.getBody().getConfig().getIssuer());
    }

    @Test
    public void testUpdateProvider() {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        Mockito.when(provisioning.create(Mockito.any(), Mockito.anyString())).thenReturn(mfaProvider);
        Mockito.when(provisioning.update(Mockito.any(), Mockito.anyString())).thenReturn(mfaProvider);

        mfaProvider = endpoint.createMfaProvider(mfaProvider).getBody();
        mfaProvider.setId("providerId");
        mfaProvider.setName("UpdatedName");

        MfaProvider<GoogleMfaProviderConfig> updatedMfaProvider = endpoint.updateMfaProvider(mfaProvider.getId(), mfaProvider).getBody();

        assertEquals("UpdatedName", updatedMfaProvider.getName());
        assertEquals(mfaProvider.getId(), updatedMfaProvider.getId());
    }

    @Test
    public void testGetMfaProviders() {
        MfaProvider<GoogleMfaProviderConfig> mockProviderResponse = constructGoogleProvider();
        when(provisioning.retrieveAll(anyString())).thenReturn(Collections.singletonList(mockProviderResponse));

        ResponseEntity<List<MfaProvider>> mfaGetResponse = endpoint.retrieveMfaProviders();

        assertEquals(mfaGetResponse.getBody().get(0), mockProviderResponse);
        verify(provisioning, times(1)).retrieveAll(IdentityZoneHolder.get().getId());
        assertTrue("got response", mfaGetResponse.getStatusCode().is2xxSuccessful());

    }

    @Test
    public void testGetMfaProviderById() {
        MfaProvider<GoogleMfaProviderConfig> mockProviderResponse = constructGoogleProvider();
        String providerId = "1234";
        when(provisioning.retrieve(eq(providerId), anyString())).thenReturn(mockProviderResponse);

        ResponseEntity<MfaProvider> mfaGetResponse = endpoint.retrieveMfaProviderById(providerId);

        assertEquals(mockProviderResponse, mfaGetResponse.getBody());
        verify(provisioning, times(1)).retrieve(providerId, IdentityZoneHolder.get().getId());
        assertTrue("got response", mfaGetResponse.getStatusCode().is2xxSuccessful());

    }

    @Test
    public void testDeleteMFaProvider() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        endpoint.setApplicationEventPublisher(publisher);
        MfaProvider<GoogleMfaProviderConfig> providerToDelete = constructGoogleProvider();
        String id = new RandomValueStringGenerator(5).generate();
        when(provisioning.retrieve(eq(id), anyString())).thenReturn(providerToDelete);

        ResponseEntity<MfaProvider> mfaDeleteResponse = endpoint.deleteMfaProviderById(id);
        assertEquals(providerToDelete, mfaDeleteResponse.getBody());
        ArgumentCaptor<EntityDeletedEvent> entityDeletedCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(provisioning, times(1)).retrieve(id, IdentityZoneHolder.get().getId());
        verify(publisher, times(1)).publishEvent(entityDeletedCaptor.capture());
        assertEquals(providerToDelete.getId(), ((MfaProvider)(entityDeletedCaptor.getAllValues().get(0)).getDeleted()).getId());
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider()
                .setName(new RandomValueStringGenerator(5).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig().setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256);
    }
}