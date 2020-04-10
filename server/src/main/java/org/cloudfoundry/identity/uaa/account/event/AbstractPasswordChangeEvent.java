
package org.cloudfoundry.identity.uaa.account.event;

import java.security.Principal;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 */
abstract class AbstractPasswordChangeEvent extends AbstractUaaEvent {

    private UaaUser user;

    private String message;

    public AbstractPasswordChangeEvent(String message, UaaUser user, Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        this.message = message;
        this.user = user;
    }

    public UaaUser getUser() {
        return user;
    }

    public Principal getPrincipal() {
        return getAuthentication();
    }

    public String getMessage() {
        return message;
    }

}
