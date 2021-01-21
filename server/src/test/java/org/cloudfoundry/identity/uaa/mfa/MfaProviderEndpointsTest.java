package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaProviderUpdateIsNotAllowed;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;

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

    @Rule
    public ExpectedException expection = ExpectedException.none();

    @Before
    public void setup() {

        provisioning = mock(JdbcMfaProviderProvisioning.class);
        validator = mock(GeneralMfaProviderValidator.class);
        endpoint.setMfaProviderProvisioning(provisioning);
        endpoint.setMfaProviderValidator(validator);
        IdentityZoneHolder.clear();
    }

    @Test
    public void testCreateDefaultIssuer() {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        Mockito.when(provisioning.create(Mockito.any(), Mockito.anyString())).thenReturn(mfaProvider);


        ResponseEntity<MfaProvider> mfaProviderResponseEntity = endpoint.createMfaProvider(mfaProvider);
        assertEquals(IdentityZoneHolder.get().getName(), mfaProviderResponseEntity.getBody().getConfig().getIssuer());
    }

    @Test(expected = MfaProviderUpdateIsNotAllowed.class)
    public void testUpdateProvider() throws MfaProviderUpdateIsNotAllowed {
        endpoint.updateMfaProvider();
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

    @Test
    public void testDeleteActiveProviderThrowsException() {
        MfaProvider<GoogleMfaProviderConfig> providerToDelete = constructGoogleProvider();
        String id = new RandomValueStringGenerator(5).generate();
        when(provisioning.retrieve(eq(id), anyString())).thenReturn(providerToDelete);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(providerToDelete.getName());

        expection.expect(MfaAlreadyExistsException.class);
        expection.expectMessage("MFA provider is currently active on zone: " + IdentityZoneHolder.get().getId() + ". Please deactivate it from the zone or set another MFA provider");
        endpoint.deleteMfaProviderById(id);

        IdentityZoneHolder.get().getConfig().getMfaConfig().setProviderName(null);
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider()
                .setName(new RandomValueStringGenerator(5).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig();
    }
}