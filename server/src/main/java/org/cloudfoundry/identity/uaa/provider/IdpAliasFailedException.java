package org.cloudfoundry.identity.uaa.provider;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

public class IdpAliasFailedException extends UaaException {
    @NonNull
    private final Reason reason;

    public IdpAliasFailedException(
            @NonNull final IdentityProvider<?> identityProvider,
            @NonNull final Reason reason,
            @Nullable final Throwable cause
    ) {
        super(buildMessage(identityProvider, reason), cause);
        this.reason = reason;
    }

    public HttpStatus getResponseCode() {
        return this.reason.responseCode;
    }

    private static String buildMessagePrefix(@NonNull final IdentityProvider<?> idp) {
        return String.format(
                "IdentityProvider[id=%s,zid=%s,aliasId=%s,aliasZid=%s]",
                surroundWithSingleQuotesIfPresent(idp.getId()),
                surroundWithSingleQuotesIfPresent(idp.getIdentityZoneId()),
                surroundWithSingleQuotesIfPresent(idp.getAliasId()),
                surroundWithSingleQuotesIfPresent(idp.getAliasZid())
        );
    }

    private static String buildMessage(
            @NonNull final IdentityProvider<?> idp,
            @NonNull final Reason reason
    ) {
        return String.format("%s - %s", buildMessagePrefix(idp), reason.message);
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
        );

        private final String message;
        private final HttpStatus responseCode;

        Reason(final String message, final HttpStatus responseCode) {
            this.message = message;
            this.responseCode = responseCode;
        }
    }
}
