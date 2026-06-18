package org.cloudfoundry.identity.uaa.provider.oauth;

/**
 * Thrown when a callback arrives with a state parameter that doesn't match the session's state
 * because a newer login attempt has already replaced it (e.g. two browser tabs both initiated login
 * for the same external IDP, and the older tab's callback arrived after the newer tab's state was stored).
 */
class ConcurrentLoginAttemptException extends RuntimeException {

    private final String originKey;

    ConcurrentLoginAttemptException(String originKey) {
        super("Concurrent login attempt detected for origin: " + originKey);
        this.originKey = originKey;
    }

    String getOriginKey() {
        return originKey;
    }
}
