package org.cloudfoundry.identity.uaa.spiffe.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.spiffe.JwtSvidSigner;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Published when {@code POST /jwt-svid/sign} mints a JWT-SVID, so there is an audit trail of
 * which agent obtained which workload's identity, and when.
 */
public class JwtSvidIssuedEvent extends AbstractUaaEvent {

    private final String audience;

    public JwtSvidIssuedEvent(JwtSvidSigner.JwtSvidResult result, String audience, Authentication principal, String zoneId) {
        super(result, principal, zoneId);
        this.audience = audience;
    }

    @Override
    public JwtSvidSigner.JwtSvidResult getSource() {
        return (JwtSvidSigner.JwtSvidResult) super.getSource();
    }

    @Override
    public AuditEvent getAuditEvent() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("spiffe_id", getSource().spiffeId());
        data.put("audience", audience);
        return createAuditRecord(clientId(getAuthentication()), AuditEventType.JwtSvidIssuedEvent,
                getOrigin(getAuthentication()), JsonUtils.writeValueAsString(data));
    }

    private static String clientId(Authentication authentication) {
        if (authentication instanceof OAuth2Authentication oAuth2Authentication) {
            return oAuth2Authentication.getOAuth2Request().getClientId();
        }
        return authentication == null ? null : authentication.getName();
    }
}
