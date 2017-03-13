package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

public class ClientLockoutPolicyRetriever implements LockoutPolicyRetriever {

    private LockoutPolicy defaultLockoutPolicy;
    private LockoutPolicy disabledLockoutPolicy = new LockoutPolicy();

    private boolean isEnabled;

    @Override
    public LockoutPolicy getLockoutPolicy() {
        if(isEnabled) {
            LockoutPolicy res = IdentityZoneHolder.get().getConfig().getClientLockoutPolicy();
            return res.getLockoutAfterFailures() != -1 ? res : defaultLockoutPolicy;
        } else {
            return disabledLockoutPolicy;
        }
    }

    @Override
    public LockoutPolicy getDefaultLockoutPolicy() {
        return defaultLockoutPolicy;
    }

    @Override
    public void setDefaultLockoutPolicy(LockoutPolicy defaultLockoutPolicy) {
        this.defaultLockoutPolicy = defaultLockoutPolicy;
    }

    public ClientLockoutPolicyRetriever setEnabled(boolean enabled) {
        isEnabled = enabled;
        return this;
    }
}
