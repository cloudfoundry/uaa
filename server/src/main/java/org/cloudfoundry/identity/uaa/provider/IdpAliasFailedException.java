package org.cloudfoundry.identity.uaa.provider;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

public class IdpAliasFailedException extends UaaException {
    private static final String ERROR = "alias_creation_failed";

    public IdpAliasFailedException(
            @NonNull final IdentityProvider<?> identityProvider,
            @NonNull final Reason reason,
            @Nullable final Throwable cause
    ) {
        this(
                identityProvider.getId(),
                identityProvider.getIdentityZoneId(),
                identityProvider.getAliasId(),
                identityProvider.getAliasZid(),
                reason,
                cause
        );
    }

    public IdpAliasFailedException(
            @Nullable final String idpId,
            @Nullable final String idzId,
            @Nullable final String aliasId,
            @Nullable final String aliasZid,
            @NonNull final Reason reason,
            @Nullable final Throwable cause
    ) {
        super(cause, ERROR, buildMessage(idpId, idzId, aliasId, aliasZid, reason), reason.responseCode.value());
    }

    private static String buildMessagePrefix(
            @Nullable final String idpId,
            @Nullable final String idzId,
            @Nullable final String aliasId,
            @Nullable final String aliasZid
    ) {
        return String.format(
                "IdentityProvider[id=%s,zid=%s,aliasId=%s,aliasZid=%s]",
                surroundWithSingleQuotesIfPresent(idpId),
                surroundWithSingleQuotesIfPresent(idzId),
                surroundWithSingleQuotesIfPresent(aliasId),
                surroundWithSingleQuotesIfPresent(aliasZid)
        );
    }

    private static String buildMessage(
            @Nullable final String idpId,
            @Nullable final String idzId,
            @Nullable final String aliasId,
            @Nullable final String aliasZid,
            @NonNull final Reason reason
    ) {
        final String messagePrefix = buildMessagePrefix(idpId, idzId, aliasId, aliasZid);
        return String.format("%s - %s", messagePrefix, reason.message);
    }

    private static String surroundWithSingleQuotesIfPresent(@Nullable final String input) {
        return Optional.ofNullable(input).map(it -> "'" + it + "'").orElse(null);
    }

    public enum Reason {
        ORIGIN_KEY_ALREADY_USED_IN_ALIAS_ZONE(
                "An IdP with this origin already exists in the alias zone.",
                HttpStatus.CONFLICT
        ),
        ALIAS_ZONE_DOES_NOT_EXIST(
                "The referenced alias zone does not exist.",
                HttpStatus.UNPROCESSABLE_ENTITY
        ),
        COULD_NOT_BREAK_REFERENCE_TO_ALIAS(
                "Could not break reference to alias IdP.",
                HttpStatus.UNPROCESSABLE_ENTITY
        );

        private final String message;
        private final HttpStatus responseCode;

        Reason(final String message, final HttpStatus responseCode) {
            this.message = message;
            this.responseCode = responseCode;
        }
    }
}
