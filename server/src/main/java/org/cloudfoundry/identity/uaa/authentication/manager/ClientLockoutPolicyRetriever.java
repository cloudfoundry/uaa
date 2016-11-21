package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

public class ClientLockoutPolicyRetriever implements LockoutPolicyRetriever {

    private LockoutPolicy defaultLockoutPolicy;
    
    @Override
    public LockoutPolicy getLockoutPolicy() {
        LockoutPolicy res = IdentityZoneHolder.get().getConfig().getClientLockoutPolicy();
        return res.getLockoutAfterFailures() != -1 ? res : defaultLockoutPolicy;
    }

    @Override
    public LockoutPolicy getDefaultLockoutPolicy() {
        return defaultLockoutPolicy;
    }

    @Override
    public void setDefaultLockoutPolicy(LockoutPolicy defaultLockoutPolicy) {
        this.defaultLockoutPolicy = defaultLockoutPolicy;
    }
}
