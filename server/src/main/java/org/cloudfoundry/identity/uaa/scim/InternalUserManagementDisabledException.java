
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class InternalUserManagementDisabledException extends UaaException {

    public InternalUserManagementDisabledException(String msg) {
        super("internal_user_management_disabled", msg, 403);
    }

}
