package org.cloudfoundry.identity.uaa.scim.services;

import org.cloudfoundry.identity.uaa.alias.AliasPropertiesInvalidException;
import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

@Component
public class ScimUserService {

    private final ScimUserAliasHandler aliasHandler;
    private final ScimUserProvisioning scimUserProvisioning;
    private final IdentityZoneManager identityZoneManager;
    private final TransactionTemplate transactionTemplate;
    private final boolean aliasEntitiesEnabled;

    public ScimUserService(
            final ScimUserAliasHandler aliasHandler,
            final ScimUserProvisioning scimUserProvisioning,
            final IdentityZoneManager identityZoneManager,
            final TransactionTemplate transactionTemplate,
            @Qualifier("aliasEntitiesEnabled") final boolean aliasEntitiesEnabled
    ) {
        this.aliasHandler = aliasHandler;
        this.scimUserProvisioning = scimUserProvisioning;
        this.identityZoneManager = identityZoneManager;
        this.transactionTemplate = transactionTemplate;
        this.aliasEntitiesEnabled = aliasEntitiesEnabled;
    }

    public ScimUser updateUser(final String userId, final ScimUser user)
            throws AliasPropertiesInvalidException, OptimisticLockingFailureException, EntityAliasFailedException {
        final ScimUser existingScimUser = scimUserProvisioning.retrieve(
                userId,
                identityZoneManager.getCurrentIdentityZoneId()
        );
        if (!aliasHandler.aliasPropertiesAreValid(user, existingScimUser)) {
            throw new AliasPropertiesInvalidException();
        }

        if (!aliasEntitiesEnabled) {
            // update user without alias handling
            return scimUserProvisioning.update(userId, user, identityZoneManager.getCurrentIdentityZoneId());
        }

        // update user and create/update alias, if necessary
        return updateUserWithAliasHandling(userId, user, existingScimUser);
    }

    private ScimUser updateUserWithAliasHandling(
            final String userId,
            final ScimUser user,
            final ScimUser existingUser
    ) {
        return transactionTemplate.execute(txStatus -> {
            final ScimUser updatedOriginalUser = scimUserProvisioning.update(
                    userId,
                    user,
                    identityZoneManager.getCurrentIdentityZoneId()
            );
            return aliasHandler.ensureConsistencyOfAliasEntity(updatedOriginalUser, existingUser);
        });
    }

}
