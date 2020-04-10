
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class PermitAllAccountLoginPolicy implements AccountLoginPolicy {
    @Override
    public boolean isAllowed(UaaUser user, Authentication a) {
        return true;
    }
}
