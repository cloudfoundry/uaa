package org.cloudfoundry.identity.uaa.scim.services;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.cloudfoundry.identity.uaa.alias.AliasPropertiesInvalidException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimUserServiceTest {
    @Mock
    private ScimUserAliasHandler scimUserAliasHandler;

    @Mock
    private ScimUserProvisioning scimUserProvisioning;

    @Mock
    private IdentityZoneManager identityZoneManager;

    @Mock
    private TransactionTemplate transactionTemplate;

    private ScimUserService scimUserService;

    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR =
            new AlphanumericRandomValueStringGenerator(8);

    private final String idzId = RANDOM_STRING_GENERATOR.generate();
    private final String userId = RANDOM_STRING_GENERATOR.generate();
    private final String origin = RANDOM_STRING_GENERATOR.generate();

    @BeforeEach
    void setUp() {
        // mock current IdZ
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(idzId);
    }

    /**
     * Test cases for both alias entities being enabled and disabled.
     */
    @Nested
    private abstract class Base {
        @Test
        final void updateShouldThrowWhenAliasPropertiesAreInvalid() {
            // mock existing user
            final ScimUser existingUser = mock(ScimUser.class);
            when(scimUserProvisioning.retrieve(userId, idzId)).thenReturn(existingUser);

            // arrange alias properties are invalid
            final ScimUser user = mock(ScimUser.class);
            when(scimUserAliasHandler.aliasPropertiesAreValid(user, existingUser)).thenReturn(false);

            assertThatExceptionOfType(AliasPropertiesInvalidException.class)
                    .isThrownBy(() -> scimUserService.updateUser(userId, user));
        }
    }

    @Nested
    class AliasEntitiesEnabled extends Base {
        @BeforeEach
        void setUp() {
            scimUserService = new ScimUserService(
                    scimUserAliasHandler,
                    scimUserProvisioning,
                    identityZoneManager,
                    transactionTemplate,
                    true
            );

            // mock transaction template
            lenient().when(transactionTemplate.execute(ArgumentMatchers.any()))
                    .then(invocationOnMock -> {
                        final TransactionCallback<?> callback = invocationOnMock.getArgument(0);
                        return callback.doInTransaction(mock(TransactionStatus.class));
                    });
        }

        @Test
        void updateShouldAlsoUpdateAliasWhenAliasPropertiesAreValid() {
            // mock existing user
            final ScimUser existingUser = buildExemplaryUser(userId, idzId, origin);
            when(scimUserProvisioning.retrieve(userId, idzId)).thenReturn(existingUser);

            // arrange alias properties are valid
            final ScimUser user = cloneScimUser(existingUser);
            user.setUserName("%s-updated".formatted(user.getUserName()));
            when(scimUserAliasHandler.aliasPropertiesAreValid(user, existingUser)).thenReturn(true);

            // arrange update of original user
            final ScimUser updatedOriginalUser = mock(ScimUser.class);
            when(scimUserProvisioning.update(userId, user, idzId)).thenReturn(updatedOriginalUser);

            scimUserService.updateUser(userId, user);

            // scimUserProvisioning.update should be called exactly once
            verify(scimUserProvisioning, times(1)).update(userId, user, idzId);

            // the scim alias handler should be called
            verify(scimUserAliasHandler, times(1)).ensureConsistencyOfAliasEntity(
                    updatedOriginalUser,
                    existingUser
            );
        }
    }

    @Nested
    class AliasEntitiesDisabled extends Base {
        @BeforeEach
        void setUp() {
            scimUserService = new ScimUserService(
                    scimUserAliasHandler,
                    scimUserProvisioning,
                    identityZoneManager,
                    transactionTemplate,
                    false
            );
        }

        @Test
        void updateShouldUpdateOnlyOriginalUserWhenAliasEnabledAndPropertiesAreValid() {
            // mock existing user
            final ScimUser existingUser = buildExemplaryUser(userId, idzId, origin);
            when(scimUserProvisioning.retrieve(userId, idzId)).thenReturn(existingUser);

            // arrange alias properties are valid
            final ScimUser user = cloneScimUser(existingUser);
            user.setUserName("%s-updated".formatted(user.getUserName()));
            when(scimUserAliasHandler.aliasPropertiesAreValid(user, existingUser)).thenReturn(true);

            scimUserService.updateUser(userId, user);

            // scimUserProvisioning.update should be called exactly once
            verify(scimUserProvisioning, times(1)).update(userId, user, idzId);

            // the scim alias handler should not be called
            verify(scimUserAliasHandler, never()).ensureConsistencyOfAliasEntity(any(), any());
        }
    }

    private static ScimUser buildExemplaryUser(
            @Nullable final String id,
            @Nonnull final String idzId,
            @Nonnull final String origin
    ) {
        final ScimUser user = new ScimUser();
        user.setId(id);
        user.setZoneId(idzId);
        user.setName(new ScimUser.Name("John", "Doe"));
        final String userName = "john.doe." + RANDOM_STRING_GENERATOR.generate();
        user.setUserName(userName);
        final ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue("%s@example.com".formatted(userName));
        user.setEmails(singletonList(email));
        user.setActive(true);
        user.setOrigin(origin);
        return user;
    }

    private static ScimUser cloneScimUser(final ScimUser user) {
        final ScimUser clone = new ScimUser();
        clone.setId(user.getId());
        clone.setExternalId(user.getExternalId());
        clone.setUserName(user.getUserName());
        clone.setEmails(user.getEmails().stream().map(it -> {
            final ScimUser.Email email = new ScimUser.Email();
            email.setValue(it.getValue());
            email.setPrimary(it.isPrimary());
            email.setType(it.getType());
            return email;
        }).toList());
        clone.setName(new ScimUser.Name(user.getName().getGivenName(), user.getName().getFamilyName()));
        final List<ScimUser.PhoneNumber> clonedPhoneNumbers;
        if (user.getPhoneNumbers() == null) {
            clonedPhoneNumbers = null;
        } else {
            clonedPhoneNumbers = user.getPhoneNumbers().stream().map(it -> {
                final ScimUser.PhoneNumber phoneNumber = new ScimUser.PhoneNumber();
                phoneNumber.setType(it.getType());
                phoneNumber.setValue(it.getValue());
                return phoneNumber;
            }).toList();
        }
        clone.setPhoneNumbers(clonedPhoneNumbers);
        clone.setActive(user.isActive());
        clone.setOrigin(user.getOrigin());
        clone.setAliasId(user.getAliasId());
        clone.setAliasZid(user.getAliasZid());
        clone.setZoneId(user.getZoneId());
        clone.setPassword(user.getPassword());
        clone.setSalt(user.getSalt());
        clone.setLastLogonTime(user.getLastLogonTime());
        clone.setPasswordLastModified(user.getPasswordLastModified());
        clone.setPreviousLogonTime(user.getPreviousLogonTime());
        return clone;
    }
}