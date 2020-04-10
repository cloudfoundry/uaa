
package org.cloudfoundry.identity.uaa.authentication.event;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Utf8;

/**
 * Event which indicates that someone tried to authenticate as a non-existent
 * user.
 * 
 * @author Luke Taylor
 */
public class UserNotFoundEvent extends AbstractUaaAuthenticationEvent {

    public UserNotFoundEvent(Authentication authentication, String zoneId) {
        super(authentication, zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {

        String name = getAuthentication().getName();

        try {
            // Store hash of name, to conceal accidental entry of sensitive info
            // (e.g. password)
            name = Utf8.decode(Base64.encode(MessageDigest.getInstance("SHA-1").digest(Utf8.encode(name))));
        } catch (NoSuchAlgorithmException shouldNeverHappen) {
            name = "NOSHA";
        }

        return createAuditRecord(name, AuditEventType.UserNotFound, getOrigin(getAuthenticationDetails()), "");

    }
}
