package org.cloudfoundry.identity.uaa;

import org.springframework.lang.Nullable;

/**
 * An entity that can have an alias in another identity zone.
 */
public interface EntityWithAlias {
    String getId();

    String getZoneId();

    @Nullable
    String getAliasId();

    void setAliasId(String aliasId);

    @Nullable
    String getAliasZid();

    void setAliasZid(String aliasZid);
}
