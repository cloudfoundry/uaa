package org.cloudfoundry.identity.uaa.oauth.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;

import java.util.HashMap;

public class TokenRevocationEvent extends AbstractUaaEvent {


    private static final long serialVersionUID = 8857827649236565674L;

    private String userId;
    private String clientId;
    private String zoneId;

    public TokenRevocationEvent(String userId, String clientId, String zoneId, Authentication authentication){
        super(authentication);
        this.userId = userId;
        this.zoneId = zoneId;
        this.clientId  = clientId;
    }

    @Override
    public AuditEvent getAuditEvent() {
        HashMap<String, String> data = new HashMap<>();
        if(clientId != null) data.put("ClientID", clientId);
        if(userId != null) data.put("UserID", userId);
        data.put("ZoneID", zoneId);

        return createAuditRecord("clientId:" + clientId + ",userId:" + userId, AuditEventType.TokenRevocationEvent, getOrigin(getAuthentication()), JsonUtils.writeValueAsString(data));
    }

    public String getClientId() {
        return clientId;
    }

    public String getUserId() {
        return userId;
    }

    public String getZoneId() {
        return zoneId;
    }
}
