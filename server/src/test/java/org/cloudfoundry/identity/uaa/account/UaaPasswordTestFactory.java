
package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * @author Dave Syer
 * 
 */
public class UaaPasswordTestFactory {

    public static UaaPrincipal getPrincipal(String id, String name, String email) {
        return new UaaPrincipal(new UaaUser(id, name, email, name, "familyName"));
    }

    public static UaaAuthentication getAuthentication(String id, String name, String email) {
        return new UaaAuthentication(getPrincipal(id, name, email), UaaAuthority.USER_AUTHORITIES, null);
    }

}
