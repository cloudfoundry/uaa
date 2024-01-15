package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
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
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
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

    @Test
    void extend_zone_allowed_groups_on_update() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        IdentityZoneEndpoints spy = Mockito.spy(endpoints);
        identityZone = createZone();
        identityZone.getConfig().getUserConfig().setAllowedGroups(List.of("sps.write", "sps.read", "idps.write", "idps.read"));
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(identityZone.getId())).thenReturn(identityZone);
        when(mockIdentityZoneProvisioning.update(same(identityZone))).thenReturn(identityZone);
        List<ScimGroup> existingScimGroups = List.of("sps.write", "sps.read").stream().
            map(e -> new ScimGroup(e, e, identityZone.getId())).collect(Collectors.toList());
        when(mockScimGroupProvisioning.retrieveAll(identityZone.getId())).thenReturn(existingScimGroups);
        spy.updateIdentityZone(identityZone, identityZone.getId());
        verify(spy, times(1)).createUserGroups(same(identityZone));
    }

    @Test
    void reduce_zone_allowed_groups_on_update_should_fail() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        identityZone = createZone();
        identityZone.getConfig().getUserConfig().setAllowedGroups(List.of("clients.admin", "clients.write", "clients.read", "clients.secret"));
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(identityZone.getId())).thenReturn(identityZone);
        List<ScimGroup> existingScimGroups = List.of("sps.write", "sps.read", "idps.write", "idps.read",
            "clients.admin", "clients.write", "clients.read", "clients.secret", "scim.write", "scim.read", "scim.create", "scim.userids",
            "scim.zones", "groups.update", "password.write", "oauth.login", "uaa.admin").stream().
            map(e -> new ScimGroup(e, e, identityZone.getId())).collect(Collectors.toList());
        when(mockScimGroupProvisioning.retrieveAll(identityZone.getId())).thenReturn(existingScimGroups);
        assertThrowsWithMessageThat(UaaException.class, () -> endpoints.updateIdentityZone(identityZone, identityZone.getId()),
            is("The identity zone user configuration contains not-allowed groups."));
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
