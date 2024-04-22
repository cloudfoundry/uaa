package org.cloudfoundry.identity.uaa.scim.endpoints;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.springframework.util.StringUtils.hasText;

import java.util.Collections;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(MockitoExtension.class)
class ScimUserEndpointsAliasTests {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(5);

    @Mock
    private IdentityZoneManager identityZoneManager;
    @Mock
    private IsSelfCheck isSelfCheck;
    @Mock
    private ScimUserProvisioning scimUserProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;
    @Mock
    private ResourceMonitor<ScimUser> scimUserResourceMonitor;
    @Mock
    private PasswordValidator passwordValidator;
    @Mock
    private ExpiringCodeStore expiringCodeStore;
    @Mock
    private ApprovalStore approvalStore;
    @Mock
    private ScimGroupMembershipManager scimGroupMembershipManager;
    @Mock
    private ScimUserAliasHandler scimUserAliasHandler;
    @Mock
    private PlatformTransactionManager platformTransactionManager;

    private ScimUserEndpoints scimUserEndpoints;
    private String idzId;
    private String origin;

    @BeforeEach
    void setUp() {
        scimUserEndpoints = new ScimUserEndpoints(
                identityZoneManager,
                isSelfCheck,
                scimUserProvisioning,
                identityProviderProvisioning,
                scimUserResourceMonitor,
                Collections.emptyMap(),
                passwordValidator,
                expiringCodeStore,
                approvalStore,
                scimGroupMembershipManager,
                scimUserAliasHandler,
                platformTransactionManager,
                false,
                500
        );

        idzId = arrangeCustomIdz();
        origin = RANDOM_STRING_GENERATOR.generate();

        lenient().when(scimUserProvisioning.createUser(
                any(ScimUser.class),
                anyString(),
                eq(idzId)
        )).then(invocationOnMock -> {
            final String id = UUID.randomUUID().toString();
            final ScimUser scimUser = invocationOnMock.getArgument(0);
            scimUser.setId(id);
            return scimUser;
        });
    }

    private String arrangeCustomIdz() {
        final String idzId = RANDOM_STRING_GENERATOR.generate();
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(idzId);
        return idzId;
    }

    private ScimUser buildScimUser() {
        final ScimUser user = new ScimUser();
        user.setOrigin(origin);
        final String email = "john.doe@example.com";
        user.setUserName(email);
        user.setName(new ScimUser.Name("John", "Doe"));
        user.setZoneId(idzId);
        user.setPrimaryEmail(email);
        return user;
    }

    @Nested
    class Create {
        @BeforeEach
        void setUp() {
            lenient().when(scimUserAliasHandler.ensureConsistencyOfAliasEntity(
                    any(ScimUser.class),
                    eq(null)
            )).then(invocationOnMock -> {
                final ScimUser scimUser = invocationOnMock.getArgument(0);
                if (hasText(scimUser.getAliasZid())) {
                    // mock ID of newly created alias user
                    scimUser.setAliasId(UUID.randomUUID().toString());
                }
                return scimUser;
            });
        }

        @Test
        void shouldThrow_WhenAliasPropertiesAreInvalid() {
            final ScimUser user = buildScimUser();

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(false);

            final MockHttpServletRequest req = new MockHttpServletRequest();
            final MockHttpServletResponse res = new MockHttpServletResponse();
            final ScimException exception = assertThrows(ScimException.class, () ->
                    scimUserEndpoints.createUser(user, req, res)
            );
            assertThat(exception.getMessage()).isEqualTo("Alias ID and/or alias ZID are invalid.");
            assertThat(exception.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
        }

        @Test
        void shouldReturnOriginalUser() {
            final ScimUser user = buildScimUser();
            user.setAliasZid(UUID.randomUUID().toString());

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(true);

            final ScimUser response = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
            assertThat(response.getAliasId()).isNotBlank();
        }
    }
}
