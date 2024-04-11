package org.cloudfoundry.identity.uaa.alias;

import java.util.Objects;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.mockito.ArgumentMatcher;
import org.springframework.lang.Nullable;

public abstract class EntityAliasHandlerEnsureConsistencyTest<T extends EntityWithAlias> {
    protected abstract T shallowCloneEntity(final T entity);

    protected abstract T buildEntityWithAliasProperties(@Nullable final String aliasId, @Nullable final String aliasZid);

    protected final String customZoneId = UUID.randomUUID().toString();

    protected abstract class NoExistingAlias_AliasFeatureEnabled {
    }

    protected abstract class NoExistingAlias_AliasFeatureDisabled {
    }

    protected abstract class ExistingAlias_AliasFeatureEnabled {
    }

    protected abstract class ExistingAlias_AliasFeatureDisabled {
    }

    protected static class EntityWithAliasMatcher<T extends EntityWithAlias> implements ArgumentMatcher<T> {
        private final String zoneId;
        private final String id;
        private final String aliasId;
        private final String aliasZid;

        public EntityWithAliasMatcher(final String zoneId, final String id, final String aliasId, final String aliasZid) {
            this.zoneId = zoneId;
            this.id = id;
            this.aliasId = aliasId;
            this.aliasZid = aliasZid;
        }

        @Override
        public boolean matches(final T argument) {
            return Objects.equals(id, argument.getId()) && Objects.equals(zoneId, argument.getZoneId())
                    && Objects.equals(aliasId, argument.getAliasId()) && Objects.equals(aliasZid, argument.getAliasZid());
        }
    }
}
