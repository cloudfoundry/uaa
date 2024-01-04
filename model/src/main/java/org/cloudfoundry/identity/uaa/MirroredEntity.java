package org.cloudfoundry.identity.uaa;

import org.springframework.lang.Nullable;

/**
 * An entity that can be mirrored from the UAA zone to a custom zone or vice-versa.
 */
public interface MirroredEntity {
    String getId();

    String getZoneId();

    @Nullable
    String getAliasId();

    void setAliasId(String aliasId);

    @Nullable
    String getAliasZid();

    void setAliasZid(String aliasZid);
}
