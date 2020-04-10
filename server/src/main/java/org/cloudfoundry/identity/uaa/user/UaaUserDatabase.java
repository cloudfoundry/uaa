
package org.cloudfoundry.identity.uaa.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Interface for loading user data for the UAA.
 */
public interface UaaUserDatabase {
    UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException;

    UaaUser retrieveUserById(String id) throws UsernameNotFoundException;

    UaaUser retrieveUserByEmail(String email, String origin) throws UsernameNotFoundException;

    UserInfo getUserInfo(String id);

    UserInfo storeUserInfo(String id, UserInfo info);

    void updateLastLogonTime(String id);
}
