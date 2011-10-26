package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Interface for loading user data for the UAA.
 *
 * Differentiates between the user object required for login, and that which is stored as
 * the principal object for an authenticated user.
 */
public interface UaaUserService {
	UaaUser getUser(String username) throws UsernameNotFoundException;

	UaaPrincipal getPrincipal(UaaUser user);
}
