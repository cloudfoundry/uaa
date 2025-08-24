package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;

public interface CompoundKeyExpirationAdder {
    void addCompoundKeyExpiration(CompoundKey compoundKey, long expirationSecond);
}
