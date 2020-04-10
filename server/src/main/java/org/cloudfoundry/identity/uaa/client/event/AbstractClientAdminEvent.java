
package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public abstract class AbstractClientAdminEvent extends AbstractUaaEvent {

    private BaseClientDetails nonExistent = new BaseClientDetails("non-existent","","","","");

    private ClientDetails client;

    public AbstractClientAdminEvent(ClientDetails client, Authentication principal, String zoneId) {
        super(principal, zoneId);
        this.client = client;
    }

    ClientDetails getClient() {
        return client;
    }

    Principal getPrincipal() {
        return getAuthentication();
    }

    abstract AuditEventType getAuditEventType();

    @Override
    public AuditEvent getAuditEvent() {
        ClientDetails clientDetails = Optional.ofNullable(getClient()).orElse(nonExistent);
        Map<String, Object> auditData = new HashMap();
        auditData.put("scopes", clientDetails.getScope());
        List<String> authorities =
            clientDetails
            .getAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());
        auditData.put("authorities", authorities);
        return createAuditRecord(
            clientDetails.getClientId(),
            getAuditEventType(),
            getOrigin(getPrincipal()),
            JsonUtils.writeValueAsString(auditData)
        );
    }

}
