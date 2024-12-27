package org.cloudfoundry.identity.uaa;

import java.util.Optional;

import org.springframework.lang.Nullable;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * An entity that can have an alias in another identity zone.
 */
public interface EntityWithAlias {
    String getId();

    String getZoneId();

    /**
     * @return the ID of the alias entity
     */
    @Nullable
    String getAliasId();

    /**
     * @param aliasId the ID of the alias entity
     */
    void setAliasId(String aliasId);

    /**
     * @return the ID of the identity zone in which an alias of the entity is maintained
     */
    @Nullable
    String getAliasZid();

    /**
     * @param aliasZid the ID of the identity zone in which an alias of the entity is maintained
     */
    void setAliasZid(String aliasZid);

    /**
     * Get a description of the entity including its alias properties, e.g., for logging.
     */
    @JsonIgnore
    default String getAliasDescription() {
        return "%s[id=%s,zid=%s,aliasId=%s,aliasZid=%s]".formatted(
                getClass().getSimpleName(),
                surroundWithSingleQuotesIfPresent(getId()),
                surroundWithSingleQuotesIfPresent(getZoneId()),
                surroundWithSingleQuotesIfPresent(getAliasId()),
                surroundWithSingleQuotesIfPresent(getAliasZid())
        );
    }

    private static String surroundWithSingleQuotesIfPresent(@Nullable final String input) {
        return Optional.ofNullable(input).map(it -> "'" + it + "'").orElse(null);
    }
}
