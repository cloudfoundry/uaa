
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import java.util.Date;

/**
 * @author Dave Syer
 *
 */
public class UaaUserTestFactory {

    public static UaaUser getUser(String id, String name, String email, String givenName, String familyName) {
        return new UaaUser(id, name, "", email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
                        new Date(), OriginKeys.UAA, "externalId", false, IdentityZoneHolder.get().getId(), id, new Date());
    }

    public static UaaUser getAdminUser(String id, String name, String email, String givenName, String familyName) {
        return new UaaUser(id, name, "", email, UaaAuthority.ADMIN_AUTHORITIES, givenName, familyName, new Date(),
                        new Date(), OriginKeys.UAA, "externalId", false, IdentityZoneHolder.get().getId(), id, new Date());
    }

}
