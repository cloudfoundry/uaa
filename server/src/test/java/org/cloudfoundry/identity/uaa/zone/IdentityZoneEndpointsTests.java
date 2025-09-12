package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.KeyProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.KeyProviderValidator;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.validation.BindingResult;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IdentityZoneEndpointsTests {

    private IdentityZone identityZone;

    @Mock
    private IdentityZoneProvisioning mockIdentityZoneProvisioning;

    @Mock
    private ScimGroupProvisioning mockScimGroupProvisioning;

    @Mock
    private KeyProviderProvisioning keyProviderProvisioning;

    @Mock
    private KeyProviderValidator keyProviderValidator;


    @Mock
    private IdentityZoneValidator mockIdentityZoneValidator;

    @Mock
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;

    @Mock
    private IdentityZoneEndpointClientRegistrationService mockIdentityZoneEndpointClientRegistrationService;

    @InjectMocks
    private IdentityZoneEndpoints endpoints;

    @Test
    void create_zone() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneProvisioning.create(any())).then(invocation -> invocation.getArgument(0));
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        identityZone = createZone();
        endpoints.createIdentityZone(identityZone, mock(BindingResult.class));
        verify(mockIdentityZoneProvisioning, times(1)).create(same(identityZone));
    }

    @Test
    void groups_are_created() {
        identityZone = createZone();
        endpoints.createUserGroups(identityZone);
        ArgumentCaptor<ScimGroup> captor = ArgumentCaptor.forClass(ScimGroup.class);
        List<String> defaultGroups = identityZone.getConfig().getUserConfig().getDefaultGroups();
        verify(mockScimGroupProvisioning, times(defaultGroups.size())).createOrGet(captor.capture(), eq(identityZone.getId()));
        assertEquals(defaultGroups.size(), captor.getAllValues().size());
        assertThat(defaultGroups,
                containsInAnyOrder(
                        captor.getAllValues().stream().map(
                                ScimGroup::getDisplayName
                        ).toArray(String[]::new)
                )
        );
    }

    @Test
    void group_creation_called_on_create() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneProvisioning.create(any())).then(invocation -> invocation.getArgument(0));
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        IdentityZoneEndpoints spy = Mockito.spy(endpoints);
        identityZone = createZone();
        spy.createIdentityZone(identityZone, mock(BindingResult.class));
        verify(spy, times(1)).createUserGroups(same(identityZone));
    }

    @Test
    void group_creation_called_on_update() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        IdentityZoneEndpoints spy = Mockito.spy(endpoints);
        identityZone = createZone();
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(identityZone.getId())).thenReturn(identityZone);
        when(mockIdentityZoneProvisioning.update(same(identityZone))).thenReturn(identityZone);
        spy.updateIdentityZone(identityZone, identityZone.getId());
        verify(spy, times(1)).createUserGroups(same(identityZone));
    }

    @Test
    void remove_keys_from_map() {
        identityZone = createZone();

        endpoints.removeKeys(identityZone);

        assertNull(identityZone.getConfig().getSamlConfig().getPrivateKey());
        assertNull(identityZone.getConfig().getSamlConfig().getPrivateKeyPassword());
        identityZone.getConfig().getSamlConfig().getKeys().forEach((key, value) -> {
            assertNull(value.getKey());
            assertNull(value.getPassphrase());
        });
    }

    @Test
    void restore_keys() {
        remove_keys_from_map();
        IdentityZone original = createZone();
        endpoints.restoreSecretProperties(original, identityZone);


        assertNotNull(identityZone.getConfig().getSamlConfig().getPrivateKey());
        assertNotNull(identityZone.getConfig().getSamlConfig().getPrivateKeyPassword());
        identityZone.getConfig().getSamlConfig().getKeys().forEach((key, value) -> {
            assertNotNull(value.getKey());
            assertNotNull(value.getPassphrase());
        });

    }

    private static IdentityZone createZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        IdentityZoneConfiguration config = zone.getConfig();
        assertNotNull(config);
        zone.getConfig().getSamlConfig().setPrivateKey("private");
        zone.getConfig().getSamlConfig().setPrivateKeyPassword("passphrase");
        zone.getConfig().getSamlConfig().setCertificate("certificate");
        zone.getConfig().getSamlConfig().addAndActivateKey("active", new SamlKey("private1", "passphrase1", "certificate1"));

        assertNotNull(zone.getConfig().getSamlConfig().getPrivateKey());
        assertNotNull(zone.getConfig().getSamlConfig().getPrivateKeyPassword());
        zone.getConfig().getSamlConfig().getKeys().forEach((key, value) -> {
            assertNotNull(value.getKey());
            assertNotNull(value.getPassphrase());
        });
        return zone;
    }
}
