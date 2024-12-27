package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;

public interface CompoundKeyPurger {
    boolean removeCompoundKey(CompoundKey compoundKey, long expirationSecond);
}
