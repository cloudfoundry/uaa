
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;


/**
 * This is an interface thats abstracts logic for retrieving both User and Client lockout policies
 *
 */
public interface LockoutPolicyRetriever {
    LockoutPolicy getLockoutPolicy();
    
    LockoutPolicy getDefaultLockoutPolicy();
    
    void setDefaultLockoutPolicy(LockoutPolicy defaultLockoutPolicy);
}
