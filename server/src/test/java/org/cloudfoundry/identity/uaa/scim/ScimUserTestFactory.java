
package org.cloudfoundry.identity.uaa.scim;

import java.util.UUID;

/**
 * @author Dave Syer
 * 
 */
public class ScimUserTestFactory {

    public static ScimUser getScimUser(String userName, String email, String givenName, String familyName) {
        ScimUser user = new ScimUser(UUID.randomUUID().toString(), userName, givenName, familyName);
        if (email != null) {
            user.addEmail(email);
        }
        return user;
    }

}
