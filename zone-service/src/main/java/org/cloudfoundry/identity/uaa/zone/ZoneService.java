package org.cloudfoundry.identity.uaa.zone;

import java.net.URI;

import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.Zone;
import org.cloudfoundry.identity.uaa.zone.model.ZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.ZoneResponse;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

public class ZoneService {

    public static final String X_IDENTITY_ZONE_ID = "X-Identity-Zone-Id";

    private final IdentityZoneProvisioning zoneProvisioning;
    private final String uaaDashboardUri;

    public ZoneService(IdentityZoneProvisioning zoneProvisioning, String uaaDashboardUri) {
        this.zoneProvisioning = zoneProvisioning;
        this.uaaDashboardUri = uaaDashboardUri;
    }

    public ZoneResponse getZoneDetails(String zoneName) {
        IdentityZone identityZone = zoneProvisioning.retrieveByName(zoneName);
        Zone zone = new Zone(null, identityZone.getSubdomain());
        String uaaUri = ServletUriComponentsBuilder.fromCurrentContextPath().toUriString();
        String zoneUri = getZoneUri(identityZone.getSubdomain(), uaaUri);
        ConnectionDetails connectionDetails = buildConnectionDetails(zoneName, identityZone, zoneUri);
        return new ZoneResponse(zoneName, zone, connectionDetails);
    }

    private ConnectionDetails buildConnectionDetails(String zoneName, IdentityZone identityZone,
                                                            String zoneUri) {
        ConnectionDetails connectionDetails = new ConnectionDetails();
        connectionDetails.setUri(zoneUri);
        connectionDetails.setIssuerId(zoneUri + "/oauth/token");
        connectionDetails.setSubdomain(identityZone.getSubdomain());
        connectionDetails.setDashboardUri(uaaDashboardUri);
        ZoneHeader zoneHeader = new ZoneHeader(X_IDENTITY_ZONE_ID, identityZone.getId());
        connectionDetails.setZone(zoneHeader);
        return connectionDetails;
    }

    private String getZoneUri(String subdomain, String uaaUri) {
        URI uaaUriObject = URI.create(uaaUri);
        String currentUAAHostName = uaaUriObject.getHost();
        URI newUAARoute = URI
            .create(uaaUriObject.toString().replace(currentUAAHostName, subdomain + "." + currentUAAHostName));
        return newUAARoute.toString();
    }
}
