package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.InvalidClientSecretException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.ZoneAwareClientSecretPolicyValidator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(PollutionPreventionExtension.class)
class ClientAdminEndpointsTests {

    private ClientAdminEndpoints endpoints;

    private UaaClientDetails input;

    private final ClientDetailsModification[] inputs = new ClientDetailsModification[5];

    private UaaClientDetails detail;

    private final UaaClientDetails[] details = new UaaClientDetails[inputs.length];

    private QueryableResourceManager<ClientDetails> clientDetailsService;

    private SecurityContextAccessor mockSecurityContextAccessor;

    private MultitenantClientServices clientRegistrationService;

    private AuthenticationManager mockAuthenticationManager;

    private ClientAdminEndpointsValidator clientDetailsValidator;

    private static final Set<String> SINGLE_REDIRECT_URL = Collections.singleton("http://redirect.url");

    private final IdentityZone testZone = new IdentityZone();

    private abstract static class NoOpClientDetailsResourceManager implements QueryableResourceManager<ClientDetails> {
        @Override
        public ClientDetails create(ClientDetails resource, String zoneId) {
            Map<String, Object> additionalInformation = new HashMap<>(resource.getAdditionalInformation());
            additionalInformation.put("lastModified", 1463510591);

            UaaClientDetails altered = new UaaClientDetails(resource);
            altered.setAdditionalInformation(additionalInformation);

            return altered;
        }
    }

    @BeforeEach
    void setUp() {
        testZone.setId("testzone");
        mockSecurityContextAccessor = Mockito.mock(SecurityContextAccessor.class);

        clientDetailsService = Mockito.mock(NoOpClientDetailsResourceManager.class);
        when(clientDetailsService.create(any(ClientDetails.class), anyString())).thenCallRealMethod();
        clientRegistrationService = Mockito.mock(MultitenantClientServices.class, withSettings().extraInterfaces(SystemDeletable.class));
        mockAuthenticationManager = Mockito.mock(AuthenticationManager.class);
        ApprovalStore approvalStore = mock(ApprovalStore.class);
        clientDetailsValidator = new ClientAdminEndpointsValidator(mockSecurityContextAccessor, new IdentityZoneManagerImpl());
        clientDetailsValidator.setClientDetailsService(clientDetailsService);
        clientDetailsValidator.setClientSecretValidator(
                new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6)));

        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);

        endpoints = spy(new ClientAdminEndpoints(
                mockSecurityContextAccessor,
                new IdentityZoneManagerImpl(),
                clientDetailsValidator,
                mockAuthenticationManager,
                mock(ResourceMonitor.class),
                approvalStore,
                clientRegistrationService,
                clientDetailsService,
                5));

        input = new UaaClientDetails();
        input.setClientId("foo");
        input.setClientSecret("secret");
        input.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        input.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);

        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = new ClientDetailsModification();
            inputs[i].setClientId("foo-" + i);
            inputs[i].setClientSecret("secret-" + i);
            inputs[i].setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
            inputs[i].setRegisteredRedirectUri(new HashSet<>(Collections.singletonList("https://foo-" + i)));
            inputs[i].setAccessTokenValiditySeconds(300);
        }

        detail = new UaaClientDetails(input);
        detail.setResourceIds(Collections.singletonList("none"));
        // refresh token is added automatically by endpoint validation
        detail.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "refresh_token"));
        detail.setScope(Collections.singletonList("uaa.none"));
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));

        for (int i = 0; i < details.length; i++) {
            details[i] = new UaaClientDetails(inputs[i]);
            details[i].setResourceIds(Collections.singletonList("none"));
            // refresh token is added automatically by endpoint validation
            details[i].setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "refresh_token"));
            details[i].setScope(Collections.singletonList("uaa.none"));
            details[i].setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        }

        endpoints.setApplicationEventPublisher(
                new ApplicationEventPublisher() {
                    @Override
                    public void publishEvent(ApplicationEvent event) {
                        if (event instanceof EntityDeletedEvent deletedEvent) {
                            ClientDetails client = (ClientDetails) deletedEvent.getDeleted();
                            clientRegistrationService.removeClientDetails(client.getClientId());
                        }
                    }

                    @Override
                    public void publishEvent(Object event) {
                        // do nothing
                    }
                }
        );
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void validateClientsTransferAutoApproveScopeSet() {
        List<String> scopes = Arrays.asList("scope1", "scope2");
        input.setAutoApproveScopes(new HashSet<>(scopes));
        ClientDetails test = clientDetailsValidator.validate(input, Mode.CREATE);
        for (String scope : scopes) {
            assertThat(test.isAutoApprove(scope)).as("Client should have " + scope + " autoapprove.").isTrue();
        }
    }

    @Test
    void statistics() {
        assertThat(endpoints.getClientDeletes()).isZero();
        assertThat(endpoints.getClientSecretChanges()).isZero();
        assertThat(endpoints.getClientJwtChanges()).isZero();
        assertThat(endpoints.getClientUpdates()).isZero();
        assertThat(endpoints.getErrorCounts()).isEmpty();
        assertThat(endpoints.getTotalClients()).isZero();
    }

    @Test
    void createClientDetails() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
        assertThat(result.getAdditionalInformation()).containsEntry("lastModified", 1463510591);
    }

    @Test
    void createClientDetailsWithSecondarySecret() {
        final var secondarySecret = "secondarySecret";
        final var clientDetailsCreation = createClientDetailsCreation(input);
        clientDetailsCreation.setSecondaryClientSecret(secondarySecret);

        ClientDetails result = endpoints.createClientDetails(clientDetailsCreation);

        assertThat(result.getClientSecret()).isNull();
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
        verify(clientRegistrationService).addClientSecret(clientDetailsCreation.getClientId(), secondarySecret,
                IdentityZoneHolder.get().getId());
    }

    @Test
    void createClientDetailsWithSecretLengthLessThanMinLength() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(7, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithSecretLengthGreaterThanMaxLength() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithSecretRequireDigit() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 1, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithSecretRequireUppercase() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 1, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithSecretRequireLowercase() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 1, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithSecretRequireSpecialCharacter() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 1, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithSecretSatisfyingComplexPolicy() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(6, 255, 1, 1, 1, 1, 6));
        IdentityZoneHolder.set(testZone);
        String complexPolicySatisfyingSecret = "Secret1@";
        input.setClientSecret(complexPolicySatisfyingSecret);
        detail.setClientSecret(complexPolicySatisfyingSecret);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        verify(clientDetailsService).create(detail, testZone.getId());
        assertThat(result.getAdditionalInformation()).containsEntry("lastModified", 1463510591);
    }

    @Test
    void createClientDetailsWithSecondarySecretNotMeetingSecretPolicy() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(15, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);

        final var clientDetailsCreation = createClientDetailsCreation(input);
        clientDetailsCreation.setClientSecret("compliantSecret");
        clientDetailsCreation.setSecondaryClientSecret("tooShort");

        assertThatThrownBy(() -> endpoints.createClientDetails(clientDetailsCreation))
                .isInstanceOf(InvalidClientSecretException.class);
    }

    @Test
    void get_restricted_scopes_list() {
        assertThat(endpoints.getRestrictedClientScopes()).isEqualTo(new UaaScopes().getUaaScopes());
    }

    @Test
    void cannotCreateRestrictedClientSpScopes() {
        List<String> badScopes = new ArrayList<>();
        badScopes.add("sps.write");
        badScopes.add("sps.read");
        badScopes.add("zones.*.sps.read");
        badScopes.add("zones.*.sps.write");
        badScopes.add("zones.*.idps.write");
        input.setScope(badScopes);
        for (String scope :
                badScopes) {
            input.setScope(Collections.singletonList(scope));
            try {
                endpoints.createRestrictedClientDetails(input);
                fail("no error thrown for restricted scope " + scope);
            } catch (InvalidClientDetailsException e) {
                assertThat(e.getMessage()).contains("is a restricted scope.");
            }
        }
    }

    @Test
    void cannotCreateRestrictedClientInvalidScopes() {
        input.setClientId("admin");
        input.setScope(new UaaScopes().getUaaScopes());
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createRestrictedClientDetails(input));
    }

    @Test
    void cannotCreateRestrictedClientInvalidAuthorities() {
        input.setAuthorities(new UaaScopes().getUaaAuthorities());
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createRestrictedClientDetails(input));
    }

    @Test
    void cannotUpdateRestrictedClientInvalidScopes() {
        input.setScope(new UaaScopes().getUaaScopes());
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.updateRestrictedClientDetails(input, input.getClientId()));
    }

    @Test
    void cannotUpdateRestrictedClientInvalidAuthorities() {
        input.setAuthorities(new UaaScopes().getUaaAuthorities());
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.updateRestrictedClientDetails(input, input.getClientId()));
    }

    @Test
    void multipleCreateClientDetailsNullArray() {
        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> endpoints.createClientDetailsTx(null));
    }

    @Test
    void multipleCreateClientDetailsEmptyArray() {
        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> endpoints.createClientDetailsTx(new ClientDetailsModification[0]));
    }

    @Test
    void multipleCreateClientDetailsNonExistent() {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId("unknown");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetailsTx(new ClientDetailsModification[]{detailsModification}));
    }

    @Test
    void multipleUpdateClientDetailsNullArray() {
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.updateClientDetailsTx(null));
    }

    @Test
    void multipleUpdateClientDetailsEmptyArray() {
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.updateClientDetailsTx(new ClientDetailsModification[0]));
    }

    @Test
    void multipleCreateClientDetails() {
        ClientDetails[] results = endpoints.createClientDetailsTx(inputs);
        assertThat(results).as("We should have created " + inputs.length + " clients.").hasSameSizeAs(inputs);
        for (int i = 0; i < inputs.length; i++) {
            ClientDetails result = results[i];
            assertThat(result.getClientSecret()).isNull();
        }
    }

    @Test
    void createClientDetailsWithReservedId() {
        input.setClientId("uaa");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createClientDetailsWithInvalidClientId() {
        input.setClientId("foo/bar");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
        input.setClientId("foo\\bar");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createMultipleClientDetailsWithReservedId() {
        inputs[inputs.length - 1].setClientId("uaa");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetailsTx(inputs));
    }

    @Test
    void createClientDetailsWithNoGrantType() {
        input.setAuthorizedGrantTypes(Collections.emptySet());
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
    }

    @Test
    void createMultipleClientDetailsWithNoGrantType() {
        inputs[inputs.length - 1].setAuthorizedGrantTypes(Collections.emptySet());
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetailsTx(inputs));
    }

    @Test
    void createClientDetailsWithClientCredentials() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        input.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
    }

    @Test
    void createClientDetailsWithJwtBearer() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        input.setScope(Collections.singletonList(input.getClientId() + ".scope"));
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        detail.setScope(input.getScope());
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
    }

    @Test
    void createClientDetailsWithAdditionalInformation() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        detail.setAdditionalInformation(input.getAdditionalInformation());
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
    }

    @Test
    void resourceServerCreation() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.resource"));
        input.setScope(Collections.singletonList(detail.getClientId() + ".some"));
        input.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        endpoints.createClientDetails(createClientDetailsCreation(input));
    }

    @Test
    void createClientDetailsWithPasswordGrant() {
        input.setAuthorizedGrantTypes(Collections.singletonList("password"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(input)));
        verify(clientRegistrationService, never()).addClientDetails(any());
    }

    @Test
    void findClientDetails() {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true, IdentityZoneHolder.get().getId())).thenReturn(
                Collections.singletonList(detail));
        SearchResults<?> result = endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
        assertThat(result.getResources()).hasSize(1);
        verify(clientDetailsService).query("filter", "sortBy", true, IdentityZoneHolder.get().getId());

        result = endpoints.listClientDetails("", "filter", "sortBy", "ascending", 1, 100);
        assertThat(result.getResources()).hasSize(1);
    }

    @Test
    void findClientDetailsInvalidFilter() {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true, IdentityZoneHolder.get().getId())).thenThrow(new IllegalArgumentException());
        assertThatExceptionOfType(UaaException.class).isThrownBy(() -> endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100));
    }

    @Test
    void findClientDetailsTestAttributeFilter() {
        when(clientDetailsService.query(anyString(), anyString(), anyBoolean(), eq(IdentityZoneHolder.get().getId()))).thenReturn(Arrays.asList(inputs));
        for (String attribute : Arrays.asList("client_id", "resource_ids", "authorized_grant_types", "redirect_uri", "access_token_validity", "refresh_token_validity", "autoapprove", "additionalinformation")) {
            SearchResults<Map<String, Object>> result = (SearchResults<Map<String, Object>>) endpoints.listClientDetails(attribute, "client_id pr", "sortBy", "ascending", 1, 100);
            validateAttributeResults(result, Collections.singletonList(attribute));
        }
    }

    private void validateAttributeResults(SearchResults<Map<String, Object>> result, List<String> attributes) {
        assertThat(result.getResources()).hasSize(5);
        for (String s : attributes) {
            result.getResources().forEach(map -> assertThat(map).containsKey(s));
        }
    }

    @Test
    void updateClientDetailsWithNullCallerAndInvalidScope() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new UaaClientDetails(input));
        input.setScope(Collections.singletonList("read"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.updateClientDetails(input, input.getClientId()));
        verify(clientRegistrationService, never()).updateClientDetails(any());
    }

    @Test
    void nonExistentClient1() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenThrow(new InvalidClientDetailsException(""));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.getClientDetails(input.getClientId()));
    }

    @Test
    void nonExistentClient2() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenThrow(new BadClientCredentialsException());
        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> endpoints.getClientDetails(input.getClientId()));
    }

    @Test
    void getClientDetails() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(input);
        input.setScope(Collections.singletonList(input.getClientId() + ".read"));
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = endpoints.getClientDetails(input.getClientId());
        assertThat(result.getClientSecret()).isNull();
        assertThat(result.getAdditionalInformation()).isEqualTo(input.getAdditionalInformation());
    }

    @Test
    void updateClientDetails() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new UaaClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setScope(Collections.singletonList(input.getClientId() + ".read"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertThat(result.getClientSecret()).isNull();
        detail.setScope(Collections.singletonList(input.getClientId() + ".read"));
        verify(clientRegistrationService).updateClientDetails(detail, "testzone");
    }

    @Test
    void updateClientDetailsWithAdditionalInformation() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new UaaClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setScope(Collections.singletonList(input.getClientId() + ".read"));
        input.setAdditionalInformation(Collections.singletonMap(ClientConstants.ALLOW_PUBLIC, false));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertThat(result.getClientSecret()).isNull();
        detail.setScope(input.getScope());
        detail.setAdditionalInformation(Collections.emptyMap());
        verify(clientRegistrationService).updateClientDetails(detail, "testzone");
    }

    @Test
    void partialUpdateClientDetails() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        UaaClientDetails updated = new UaaClientDetails(detail);
        input = new UaaClientDetails();
        input.setClientId("foo");
        input.setScope(Collections.singletonList("foo.write"));
        updated.setScope(input.getScope());
        updated.setClientSecret(null);
        updated.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertThat(result.getClientSecret()).isNull();
        verify(clientRegistrationService).updateClientDetails(updated, "testzone");
    }

    @Test
    void changeSecret() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(mockAuthenticationManager.authenticate(any(Authentication.class))).thenReturn(auth);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword", "testzone");
    }

    @Test
    void addSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);

        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).addClientSecret(detail.getClientId(), "newpassword", IdentityZoneHolder.get().getId());
    }

    @Test
    void addingThirdSecretForClient() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        detail.setClientSecret("hash1 hash2");
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setOldSecret("hash1");
        change.setChangeMode(ADD);
        assertThatThrownBy(() -> endpoints.changeSecret(detail.getClientId(), change))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("client secret is either empty or client already has two secrets.");
    }

    @Test
    void deleteSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        detail.setClientSecret("hash1 hash2");
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).deleteClientSecret(detail.getClientId(), IdentityZoneHolder.get().getId());
    }

    @Test
    void deleteSecretWhenOnlyOneSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        detail.setClientSecret("hash1");
        String clientId = detail.getClientId();
        when(clientDetailsService.retrieve(clientId, IdentityZoneHolder.get().getId())).thenReturn(detail);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        assertThatThrownBy(() -> endpoints.changeSecret(clientId, change))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("client secret is either empty or client has only one secret.");
    }

    @Test
    void changeSecretDeniedForNonAdmin() {
        String clientId = detail.getClientId();
        when(clientDetailsService.retrieve(clientId, IdentityZoneHolder.get().getId())).thenReturn(detail);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        assertThatThrownBy(() -> endpoints.changeSecret(clientId, change))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("Bad request. Not permitted to change another client's secret");
    }

    @Test
    void addSecretDeniedForNonAdmin() {
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);
        assertThatThrownBy(() -> endpoints.changeSecret(detail.getClientId(), change))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("Bad request. Not permitted to change another client's secret");
    }

    @Test
    void changeSecretDeniedWhenOldSecretNotProvided() {
        String clientId = detail.getClientId();
        when(clientDetailsService.retrieve(clientId, IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockAuthenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(clientId);
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        assertThatThrownBy(() -> endpoints.changeSecret(clientId, change))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("Previous secret is required and must be valid");
    }

    @Test
    void changeSecretByAdmin() {
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("admin");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword", "testzone");
    }

    @Test
    void changeSecretDeniedTooLong() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        String complexPolicySatisfyingSecret = "Secret1@";

        when(clientDetailsService.retrieve(detail.getClientId(), testZone.getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("admin");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret(complexPolicySatisfyingSecret);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> endpoints.changeSecret(detail.getClientId(), change));
    }

    @Test
    void removeClientDetailsAdminCaller() {
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        when(clientDetailsService.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(detail);
        ClientDetails result = endpoints.removeClientDetails("foo");
        assertThat(result.getClientSecret()).isNull();
        ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(endpoints).publish(captor.capture());
        verify(clientRegistrationService).removeClientDetails("foo");
        assertThat(captor.getValue()).isNotNull();
        Object deleted = captor.getValue().getDeleted();
        assertThat(deleted).isInstanceOf(ClientDetails.class);
        assertThat(((ClientDetails) deleted).getClientId()).isEqualTo("foo");
    }

    @Test
    void scopeIsRestrictedByCaller() {
        UaaClientDetails caller = new UaaClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setScope(Collections.singletonList("some"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void validScopeIsNotRestrictedByCaller() {
        UaaClientDetails caller = new UaaClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setScope(Collections.singletonList("none"));
        endpoints.createClientDetails(createClientDetailsCreation(detail));
    }

    @Test
    void clientEndpointCannotBeConfiguredWithAnInvalidMaxCount() {
        assertThatThrownBy(() -> new ClientAdminEndpoints(null, null, null, null, null, null, null, null, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid \"clientMaxCount\" value (got 0). Should be positive number.");
    }

    @Test
    void authorityIsRestrictedByCaller() {
        UaaClientDetails caller = new UaaClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.some"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void authorityAllowedByCaller() {
        UaaClientDetails caller = new UaaClientDetails("caller", null, "uaa.none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        endpoints.createClientDetails(createClientDetailsCreation(detail));
    }

    @Test
    void cannotExpandScope() {
        UaaClientDetails caller = new UaaClientDetails();
        caller.setScope(Collections.singletonList("none"));
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        detail.setAuthorizedGrantTypes(Collections.singletonList("implicit"));
        detail.setClientSecret("hello");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void implicitClientWithNonEmptySecretIsRejected() {
        detail.setAuthorizedGrantTypes(Collections.singletonList("implicit"));
        detail.setClientSecret("hello");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejected() {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret("hello");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejectedWithNullPassword() {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret(null);
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejectedForAdmin() {
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret("hello");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void nonImplicitClientWithEmptySecretIsRejected() {
        detail.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret("");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void updateNonImplicitClientWithEmptySecretIsOk() {
        Mockito.when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        detail.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret(null);
        endpoints.updateClientDetails(detail, detail.getClientId());
    }

    @Test
    void updateNonImplicitClientAndMakeItImplicit() {
        assertThat(detail.getAuthorizedGrantTypes()).doesNotContain("implicit");
        detail.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "implicit"));
        detail.setClientSecret(null);
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.updateClientDetails(detail, detail.getClientId()));
    }

    @Test
    void invalidGrantTypeIsRejected() {
        detail.setAuthorizedGrantTypes(Collections.singletonList("not_a_grant_type"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createClientDetailsCreation(detail)));
    }

    @Test
    void handleNoSuchClient() {
        ResponseEntity<Void> result = endpoints.handleNoSuchClient(new NoSuchClientException("No such client: foo"));
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void handleClientAlreadyExists() {
        ResponseEntity<InvalidClientDetailsException> result = endpoints
                .handleClientAlreadyExists(new ClientAlreadyExistsException("No such client: foo"));
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void errorHandler() {
        ResponseEntity<InvalidClientDetailsException> result = endpoints
                .handleInvalidClientDetails(new InvalidClientDetailsException("No such client: foo"));
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(endpoints.getErrorCounts()).hasSize(1);
    }

    @Test
    void createClientWithAutoapproveScopesList() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("foo.read");
        input.setScope(scopes);
        detail.setScope(scopes);
        input.setAutoApproveScopes(autoApproveScopes);
        detail.setAutoApproveScopes(autoApproveScopes);
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        ArgumentCaptor<UaaClientDetails> clientCaptor = ArgumentCaptor.forClass(UaaClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture(), anyString());
        UaaClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertThat(created.isAutoApprove("foo.read")).isTrue();
        assertThat(created.isAutoApprove("foo.write")).isFalse();
    }

    private static void assertSetEquals(Collection<?> a, Collection<?> b) {
        assertThat(a == null && b == null || a != null && b != null && a.containsAll(b) && b.containsAll(a)).as("expected " + a + " but was " + b).isTrue();
    }

    @Test
    void createClientWithAutoapproveScopesTrue() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("true");
        input.setScope(scopes);
        detail.setScope(scopes);
        input.setAutoApproveScopes(autoApproveScopes);
        detail.setAutoApproveScopes(autoApproveScopes);
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(createClientDetailsCreation(input));
        assertThat(result.getClientSecret()).isNull();
        ArgumentCaptor<UaaClientDetails> clientCaptor = ArgumentCaptor.forClass(UaaClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture(), anyString());
        UaaClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertThat(created.isAutoApprove("foo.read")).isTrue();
        assertThat(created.isAutoApprove("foo.write")).isTrue();
    }

    @Test
    void updateClientWithAutoapproveScopesList() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new UaaClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("foo.read");

        input.setScope(scopes);
        detail.setScope(scopes);
        detail.setAutoApproveScopes(autoApproveScopes);

        ClientDetails result = endpoints.updateClientDetails(detail, input.getClientId());
        assertThat(result.getClientSecret()).isNull();
        ArgumentCaptor<UaaClientDetails> clientCaptor = ArgumentCaptor.forClass(UaaClientDetails.class);
        verify(clientRegistrationService).updateClientDetails(clientCaptor.capture(), anyString());
        UaaClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertThat(updated.isAutoApprove("foo.read")).isTrue();
        assertThat(updated.isAutoApprove("foo.write")).isFalse();
    }

    @Test
    void getClientWithFederatedJwt() {
        // Given
        UaaClientDetails uaaClientDetails = new UaaClientDetails(input);
        uaaClientDetails.setAutoApproveScopes(uaaClientDetails.getScope());
        List<ClientJwtCredential> jwtCredentials = List.of(new ClientJwtCredential("subject", "issuer", null));
        ClientJwtConfiguration clientJwtConfiguration = new ClientJwtConfiguration(jwtCredentials);
        clientJwtConfiguration.setJwksUri("http://localhost:8080/uaa/token_keys");
        clientJwtConfiguration.writeValue(uaaClientDetails);
        when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                uaaClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        // Then
        ClientDetails result = endpoints.getClientDetails(input.getClientId());
        // When
        assertThat(result.getClientSecret()).isNull();
        ClientDetailsModification modification = (ClientDetailsModification) result;
        assertThat(modification.getClientJwtCredentials()).size().isEqualTo(1);
        assertThat(modification.getJwkSet()).isNull();
        assertThat(modification.getJwksUri()).isEqualTo("http://localhost:8080/uaa/token_keys");
        ClientJwtCredential clientJwtCredential = modification.getClientJwtCredentials().getFirst();
        assertThat(clientJwtCredential).isNotNull();
        assertThat(clientJwtCredential.getIssuer()).isEqualTo("issuer");
        assertThat(clientJwtCredential.getSubject()).isEqualTo("subject");
        assertThat(clientJwtCredential.getAudience()).isNull();
        ClientDetailsModification modification2 = new ClientDetailsModification(uaaClientDetails);
        modification2.setAction("add");
        // Compare results and original with and without secret
        assertThat(modification).isNotEqualTo(modification2);
        assertThat(modification.hashCode()).isNotEqualTo(modification2.hashCode());
        uaaClientDetails.setClientSecret(null);
        ClientDetailsModification modification3 = new ClientDetailsModification(uaaClientDetails);
        assertThat(modification).isEqualTo(modification3).hasSameHashCodeAs(modification3);
        assertThat(modification.getAction()).isNotEqualTo(modification2.getAction());
        assertThat(modification.getAction()).isEqualTo(modification3.getAction());
    }

    @Test
    void updateClientWithAutoapproveScopesTrue() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new UaaClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("true");

        input.setScope(scopes);
        detail.setScope(scopes);
        detail.setAutoApproveScopes(autoApproveScopes);

        ArgumentCaptor<UaaClientDetails> clientCaptor = ArgumentCaptor.forClass(UaaClientDetails.class);
        ClientDetails result = endpoints.updateClientDetails(detail, input.getClientId());
        assertThat(result.getClientSecret()).isNull();
        verify(clientRegistrationService).updateClientDetails(clientCaptor.capture(), anyString());
        UaaClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertThat(updated.isAutoApprove("foo.read")).isTrue();
        assertThat(updated.isAutoApprove("foo.write")).isTrue();
    }

    @Test
    void createClientWithJsonWebKeyUri() {
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata, see jwks_uri
        String jwksUri = "https://any.domain.net/openid/jwks-uri";
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setClientSecret("secret");
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetailsCreation createRequest = createClientDetailsCreation(input);
        createRequest.setJsonWebKeyUri(jwksUri);
        ClientDetails result = endpoints.createClientDetails(createRequest);
        assertThat(result.getClientSecret()).isNull();
        ArgumentCaptor<UaaClientDetails> clientCaptor = ArgumentCaptor.forClass(UaaClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture(), anyString());
        UaaClientDetails created = clientCaptor.getValue();
        assertThat(ClientJwtConfiguration.parse(jwksUri)).isEqualTo(ClientJwtConfiguration.readValue(created));
    }

    @Test
    void createClientWithJsonWebKeyUriInvalid() {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setClientSecret("secret");
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetailsCreation createRequest = createClientDetailsCreation(input);
        createRequest.setJsonWebKeySet("invalid");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> endpoints.createClientDetails(createRequest));
    }

    @Test
    void addClientJwtConfigUri() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        ClientJwtChangeRequest change = new ClientJwtChangeRequest();
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata, see jwks_uri
        String jwksUri = "https://any.domain.net/openid/jwks-uri";
        change.setJsonWebKeyUri(jwksUri);
        change.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);

        ActionResult result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("Client jwt configuration is added");
        verify(clientRegistrationService, times(1)).addClientJwtConfig(detail.getClientId(), jwksUri, IdentityZoneHolder.get().getId(), false);

        change.setJsonWebKeyUri(null);
        result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("No key added");
    }

    @Test
    void addAndDeleteClientJwtFederated() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        ClientJwtChangeRequest change = new ClientJwtChangeRequest();
        change.setIssuer("https://any.domain.net");
        change.setSubject("domain-client-id");
        change.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);

        ActionResult result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("Federated client jwt configuration is added");
        verify(clientRegistrationService, times(1)).addClientJwtCredential(detail.getClientId(), new ClientJwtCredential("domain-client-id", "https://any.domain.net", null), IdentityZoneHolder.get().getId(), false);

        change.setJsonWebKeyUri(null);
        change.setSubject(null);
        change.setIssuer(null);
        result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("No key added");

        change.setIssuer("https://any.domain.net");
        change.setSubject("domain-client-id");
        change.setChangeMode(ClientJwtChangeRequest.ChangeMode.DELETE);

        result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("Federated client jwt configuration is deleted");
        verify(clientRegistrationService, times(1)).deleteClientJwtCredential(detail.getClientId(), new ClientJwtCredential("domain-client-id", "https://any.domain.net", null), IdentityZoneHolder.get().getId());

        change.setSubject(null);
        change.setIssuer(null);

        result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("No key deleted");
    }

    @Test
    void changeDeleteClientJwtConfigUri() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        ClientJwtChangeRequest change = new ClientJwtChangeRequest();
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata, see jwks_uri
        String jwksUri = "https://any.domain.net/openid/jwks-uri";
        change.setJsonWebKeyUri(jwksUri);
        change.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);

        ActionResult result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("Client jwt configuration is added");
        verify(clientRegistrationService, times(1)).addClientJwtConfig(detail.getClientId(), jwksUri, IdentityZoneHolder.get().getId(), false);

        jwksUri = "https://any.new.domain.net/openid/jwks-uri";
        change.setChangeMode(ClientJwtChangeRequest.ChangeMode.UPDATE);
        change.setJsonWebKeyUri(jwksUri);
        result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("Client jwt configuration updated");
        verify(clientRegistrationService, times(1)).addClientJwtConfig(detail.getClientId(), jwksUri, IdentityZoneHolder.get().getId(), true);

        ClientJwtConfiguration.parse(jwksUri).writeValue(detail);
        change.setChangeMode(ClientJwtChangeRequest.ChangeMode.DELETE);
        change.setJsonWebKeyUri(jwksUri);
        result = endpoints.changeClientJwt(detail.getClientId(), change);
        assertThat(result.getMessage()).isEqualTo("Client jwt configuration is deleted");
        verify(clientRegistrationService, times(1)).deleteClientJwtConfig(detail.getClientId(), jwksUri, IdentityZoneHolder.get().getId());
    }

    @Test
    void createClientWithJsonKeyWebSet() {
        // Example JWK, a key is bound to a kid, means assumption is, a key is the same if kid is the same
        String jsonJwk = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
        String jsonJwk2 = "{\"kty\":\"RSA\",\"e\":\"\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"\"}";
        String jsonJwk3 = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-2\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
        String jsonJwkSet = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}]}";
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setClientSecret("secret");
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetailsCreation createRequest = createClientDetailsCreation(input);
        createRequest.setJsonWebKeySet(jsonJwk);
        ClientDetails result = endpoints.createClientDetails(createRequest);
        assertThat(result.getClientSecret()).isNull();
        ArgumentCaptor<UaaClientDetails> clientCaptor = ArgumentCaptor.forClass(UaaClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture(), anyString());
        UaaClientDetails created = clientCaptor.getValue();
        assertThat(ClientJwtConfiguration.parse(jsonJwk)).isEqualTo(ClientJwtConfiguration.readValue(created));
        assertThat(ClientJwtConfiguration.parse(jsonJwk2)).isEqualTo(ClientJwtConfiguration.readValue(created));
        assertThat(ClientJwtConfiguration.parse(jsonJwkSet)).isEqualTo(ClientJwtConfiguration.readValue(created));
        assertThat(ClientJwtConfiguration.parse(jsonJwk3)).isNotEqualTo(ClientJwtConfiguration.readValue(created));
    }

    private ClientDetailsCreation createClientDetailsCreation(UaaClientDetails baseClientDetails) {
        final var clientDetails = new ClientDetailsCreation();
        clientDetails.setClientId(baseClientDetails.getClientId());
        clientDetails.setClientSecret(baseClientDetails.getClientSecret());
        clientDetails.setScope(baseClientDetails.getScope());
        clientDetails.setResourceIds(baseClientDetails.getResourceIds());
        clientDetails.setAuthorizedGrantTypes(baseClientDetails.getAuthorizedGrantTypes());
        clientDetails.setRegisteredRedirectUri(baseClientDetails.getRegisteredRedirectUri());
        clientDetails.setAutoApproveScopes(baseClientDetails.getAutoApproveScopes() != null ?
                baseClientDetails.getAutoApproveScopes() : Collections.emptyList());
        clientDetails.setAuthorities(baseClientDetails.getAuthorities());
        clientDetails.setAdditionalInformation(baseClientDetails.getAdditionalInformation());
        return clientDetails;
    }
}
