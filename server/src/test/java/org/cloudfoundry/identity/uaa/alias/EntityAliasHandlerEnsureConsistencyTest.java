package org.cloudfoundry.identity.uaa.alias;

import java.util.UUID;

import org.cloudfoundry.identity.uaa.EntityWithAlias;

public abstract class EntityAliasHandlerEnsureConsistencyTest<T extends EntityWithAlias> {
    protected final String customZoneId = UUID.randomUUID().toString();

    protected abstract class NoExistingAlias_AliasFeatureEnabled {
    }

    protected abstract class NoExistingAlias_AliasFeatureDisabled {
    }

    protected abstract class ExistingAlias_AliasFeatureEnabled {
    }

    protected abstract class ExistingAlias_AliasFeatureDisabled {
    }
}
