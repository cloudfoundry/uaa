package org.cloudfoundry.identity.uaa.provider;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.function.Supplier;

import org.cloudfoundry.identity.uaa.EntityAliasHandler.EntityAliasResult;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IdentityProviderEndpointsAliasTest extends IdentityProviderEndpointsTestBase {
    @Mock
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;

    @Mock
    private IdentityProviderConfigValidationDelegator mockIdentityProviderConfigValidationDelegator;

    @Mock
    private IdentityZoneManager mockIdentityZoneManager;

    @Mock
    private PlatformTransactionManager mockPlatformTransactionManager;

    @Mock
    private IdentityProviderAliasHandler mockIdentityProviderAliasHandler;

    @InjectMocks
    private IdentityProviderEndpoints identityProviderEndpoints;

    @BeforeEach
    void setup() {
        lenient().when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
    }

    @Nested
    class Create {
        @Test
        void shouldRejectInvalidAliasProperties() throws MetadataProviderException {
            final String customZoneId = randomUUID().toString();

            // alias IdP not supported for IdPs of type LDAP
            final IdentityProvider<LdapIdentityProviderDefinition> requestBody = getLdapDefinition();
            requestBody.setAliasZid(customZoneId);

            when(mockIdentityProviderAliasHandler.aliasPropertiesAreValid(requestBody, null))
                    .thenReturn(false);

            final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(requestBody, true);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldCreateAliasIdp_WhenAliasPropertiesAreSetAndValid() throws MetadataProviderException {
            final String customZoneId = randomUUID().toString();

            final Supplier<IdentityProvider<?>> requestBodyProvider = () -> {
                final IdentityProvider<?> requestBody = getExternalOAuthProvider();
                requestBody.setId(null);
                requestBody.setAliasZid(customZoneId);
                return requestBody;
            };

            final IdentityProvider<?> requestBody = requestBodyProvider.get();
            when(mockIdentityProviderAliasHandler.aliasPropertiesAreValid(requestBody, null)).thenReturn(true);

            // mock creation
            final IdentityProvider<?> persistedOriginalIdp = requestBodyProvider.get();
            final String originalIdpId = randomUUID().toString();
            persistedOriginalIdp.setId(originalIdpId);
            when(mockIdentityProviderProvisioning.create(requestBody, UAA)).thenReturn(persistedOriginalIdp);

            // mock alias handling
            final String aliasIdpId = randomUUID().toString();
            final IdentityProvider<?> persistedOriginalIdpWithAlias = requestBodyProvider.get();
            persistedOriginalIdpWithAlias.setId(originalIdpId);
            persistedOriginalIdpWithAlias.setAliasId(aliasIdpId);

            final IdentityProvider<?> persistedAliasIdp = requestBodyProvider.get();
            persistedAliasIdp.setId(aliasIdpId);
            persistedAliasIdp.setIdentityZoneId(customZoneId);
            persistedAliasIdp.setAliasId(originalIdpId);
            persistedAliasIdp.setAliasZid(UAA);

            when(mockIdentityProviderAliasHandler.ensureConsistencyOfAliasEntity(persistedOriginalIdp)).thenReturn(
                    new EntityAliasResult<>(
                            persistedOriginalIdpWithAlias,
                            persistedAliasIdp
                    )
            );

            final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(requestBody, true);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).isNotNull().isEqualTo(persistedOriginalIdpWithAlias);
        }
    }

    @Nested
    class Update {
        @Test
        void shouldReject_UpdateOfIdpWithAlias_InvalidAliasPropertyChange() throws MetadataProviderException {
            final String existingIdpId = randomUUID().toString();
            final String customZoneId = randomUUID().toString();
            final String aliasIdpId = randomUUID().toString();

            final Supplier<IdentityProvider<?>> existingIdpSupplier = () -> {
                final IdentityProvider<?> idp = getExternalOAuthProvider();
                idp.setId(existingIdpId);
                idp.setAliasZid(customZoneId);
                idp.setAliasId(aliasIdpId);
                return idp;
            };

            // original IdP with reference to an alias IdP
            final IdentityProvider<?> existingIdp = existingIdpSupplier.get();
            when(mockIdentityProviderProvisioning.retrieve(existingIdpId, IdentityZone.getUaaZoneId()))
                    .thenReturn(existingIdp);

            // invalid change: remove alias ID
            final IdentityProvider<?> requestBody = existingIdpSupplier.get();
            requestBody.setAliasId("");

            when(mockIdentityProviderAliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).thenReturn(false);

            final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
            assertThat(response.getBody()).isNotNull().isEqualTo(requestBody);
        }

        @Test
        void shouldReject_InvalidReferenceToAliasInExistingIdp() {
            final String existingIdpId = randomUUID().toString();
            final String customZoneId = randomUUID().toString();
            final String aliasIdpId = randomUUID().toString();

            final Supplier<IdentityProvider<?>> existingIdpSupplier = () -> {
                final IdentityProvider<?> idp = getExternalOAuthProvider();
                idp.setId(existingIdpId);
                idp.setAliasZid(customZoneId);
                idp.setAliasId(aliasIdpId);
                return idp;
            };

            // original IdP with (invalid) reference to an alias IdP
            final IdentityProvider<?> existingIdp = existingIdpSupplier.get();
            existingIdp.setAliasId(null);
            when(mockIdentityProviderProvisioning.retrieve(existingIdpId, IdentityZone.getUaaZoneId()))
                    .thenReturn(existingIdp);

            // valid change
            final IdentityProvider<?> requestBody = existingIdpSupplier.get();
            requestBody.setName("some-new-name");

            // validation throws illegal state exception if the reference in an existing IdP is invalid
            when(mockIdentityProviderAliasHandler.aliasPropertiesAreValid(requestBody, existingIdp))
                    .thenThrow(new IllegalStateException());

            assertThatIllegalStateException().isThrownBy(() ->
                    identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true)
            );
        }

        @Test
        void shouldCreateAlias_ValidChange() throws MetadataProviderException {
            final String existingIdpId = randomUUID().toString();

            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(UAA);

            final Supplier<IdentityProvider<?>> existingIdpSupplier = () -> {
                final IdentityProvider<?> idp = getExternalOAuthProvider();
                idp.setId(existingIdpId);
                idp.setAliasZid(null);
                idp.setAliasId(null);
                return idp;
            };

            final IdentityProvider<?> existingIdp = existingIdpSupplier.get();
            when(mockIdentityProviderProvisioning.retrieve(existingIdpId, UAA)).thenReturn(existingIdp);

            final IdentityProvider<?> requestBody = existingIdpSupplier.get();
            final String customZoneId = randomUUID().toString();
            requestBody.setAliasZid(customZoneId);

            when(mockIdentityProviderAliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).thenReturn(true);

            when(mockIdentityProviderProvisioning.update(eq(requestBody), anyString())).thenReturn(requestBody);

            final IdentityProvider<?> aliasIdp = existingIdpSupplier.get();
            final String aliasIdpId = randomUUID().toString();
            aliasIdp.setId(aliasIdpId);
            aliasIdp.setIdentityZoneId(customZoneId);
            aliasIdp.setAliasId(existingIdpId);
            aliasIdp.setAliasZid(UAA);

            final IdentityProvider<?> originalIdpAfterAliasCreation = existingIdpSupplier.get();
            originalIdpAfterAliasCreation.setAliasId(aliasIdpId);
            originalIdpAfterAliasCreation.setAliasZid(customZoneId);

            when(mockIdentityProviderAliasHandler.ensureConsistencyOfAliasEntity(requestBody))
                    .thenReturn(new EntityAliasResult<>(originalIdpAfterAliasCreation, aliasIdp));

            final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            final IdentityProvider responseBody = response.getBody();
            assertThat(responseBody).isNotNull().isEqualTo(originalIdpAfterAliasCreation);
        }
    }

    @Nested
    class Delete {
        @Test
        void shouldDeleteAliasIdpIfPresent() {
            final String idpId = randomUUID().toString();
            final String aliasIdpId = randomUUID().toString();
            final String customZoneId = randomUUID().toString();

            final IdentityProvider<?> idp = new IdentityProvider<>();
            idp.setType(OIDC10);
            idp.setId(idpId);
            idp.setIdentityZoneId(UAA);
            idp.setAliasId(aliasIdpId);
            idp.setAliasZid(customZoneId);
            when(mockIdentityProviderProvisioning.retrieve(idpId, UAA)).thenReturn(idp);

            final IdentityProvider<?> aliasIdp = new IdentityProvider<>();
            aliasIdp.setType(OIDC10);
            aliasIdp.setId(aliasIdpId);
            aliasIdp.setIdentityZoneId(customZoneId);
            aliasIdp.setAliasId(idpId);
            aliasIdp.setAliasZid(UAA);
            when(mockIdentityProviderProvisioning.retrieve(aliasIdpId, customZoneId)).thenReturn(aliasIdp);

            final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
            identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);
            doNothing().when(mockEventPublisher).publishEvent(any());

            identityProviderEndpoints.deleteIdentityProvider(idpId, true);
            final ArgumentCaptor<EntityDeletedEvent<?>> entityDeletedEventCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
            verify(mockEventPublisher, times(2)).publishEvent(entityDeletedEventCaptor.capture());

            final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().get(0);
            assertThat(firstEvent).isNotNull();
            assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
            assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idpId);

            final EntityDeletedEvent<?> secondEvent = entityDeletedEventCaptor.getAllValues().get(1);
            assertThat(secondEvent).isNotNull();
            assertThat(secondEvent.getIdentityZoneId()).isEqualTo(UAA);
            assertThat(((IdentityProvider<?>) secondEvent.getSource()).getId()).isEqualTo(aliasIdpId);
        }

        @Test
        void shouldIgnoreDanglingReferenceToAliasIdp() {
            final String idpId = randomUUID().toString();
            final String aliasIdpId = randomUUID().toString();
            final String customZoneId = randomUUID().toString();

            final IdentityProvider<?> idp = new IdentityProvider<>();
            idp.setType(OIDC10);
            idp.setId(idpId);
            idp.setIdentityZoneId(UAA);
            idp.setAliasId(aliasIdpId);
            idp.setAliasZid(customZoneId);
            when(mockIdentityProviderProvisioning.retrieve(idpId, UAA)).thenReturn(idp);

            // alias IdP is not present -> dangling reference

            final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
            identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);
            doNothing().when(mockEventPublisher).publishEvent(any());

            identityProviderEndpoints.deleteIdentityProvider(idpId, true);
            final ArgumentCaptor<EntityDeletedEvent<?>> entityDeletedEventCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);

            // should only be called for the original IdP
            verify(mockEventPublisher, times(1)).publishEvent(entityDeletedEventCaptor.capture());

            final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().get(0);
            assertThat(firstEvent).isNotNull();
            assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
            assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idpId);
        }
    }
}
