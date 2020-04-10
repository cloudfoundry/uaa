
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * Checks whether a user account is currently allowed to login.
 * 
 * @author Luke Taylor
 */
public interface AccountLoginPolicy {

    boolean isAllowed(UaaUser user, Authentication a);
}
