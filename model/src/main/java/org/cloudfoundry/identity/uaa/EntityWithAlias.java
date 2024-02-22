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

    @Nullable
    String getAliasId();

    void setAliasId(String aliasId);

    @Nullable
    String getAliasZid();

    void setAliasZid(String aliasZid);

    /**
     * Get a description of the entity including its alias properties, e.g., for logging.
     */
    @JsonIgnore
    default String getAliasDescription() {
        return String.format(
                "%s[id=%s,zid=%s,aliasId=%s,aliasZid=%s]",
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
