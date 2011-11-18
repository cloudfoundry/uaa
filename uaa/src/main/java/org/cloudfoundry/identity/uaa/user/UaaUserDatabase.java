package org.cloudfoundry.identity.uaa.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Interface for loading user data for the UAA.
 */
public interface UaaUserDatabase {
	UaaUser retrieveUserByName(String username) throws UsernameNotFoundException;
}
