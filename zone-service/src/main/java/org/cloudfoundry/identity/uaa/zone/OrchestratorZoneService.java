package org.cloudfoundry.identity.uaa.zone;

import static org.springframework.http.HttpStatus.ACCEPTED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

import java.net.URI;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

public class OrchestratorZoneService implements ApplicationEventPublisherAware {

    public static final String X_IDENTITY_ZONE_ID = "X-Identity-Zone-Id";
    public static final String CLIENT_ID = "admin";
    public static final String ZONE_AUTHORITIES = "clients.admin,clients.read,clients.write,clients.secret,idps.read,idps.write,sps" +
                                                  ".read,sps.write,scim.read,scim.write,uaa.resource";
    public static final String GRANT_TYPES = "client_credentials";
    public static final String RESOURCE_IDS = "none";
    public static final String SCOPES = "uaa.none";
    public static final String GENERATED_KEY_ID = "generated-saml-key";

    private static final java.util.Base64.Encoder base64encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());

    private final IdentityZoneProvisioning zoneProvisioning;
   private final String uaaDashboardUri;
    private ApplicationEventPublisher publisher;

    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneService.class);

    public OrchestratorZoneService(IdentityZoneProvisioning zoneProvisioning,
                                   String uaaDashboardUri) {
        this.zoneProvisioning = zoneProvisioning;
        this.uaaDashboardUri = uaaDashboardUri;
    }

    public OrchestratorZoneResponse getZoneDetails(String zoneName) {
        IdentityZone identityZone = zoneProvisioning.retrieveByName(zoneName);
        OrchestratorZone zone = new OrchestratorZone(null, identityZone.getSubdomain());
        String uaaUri = ServletUriComponentsBuilder.fromCurrentContextPath().toUriString();
        String zoneUri = getZoneUri(identityZone.getSubdomain(), uaaUri);
        ConnectionDetails connectionDetails = buildConnectionDetails(zoneName, identityZone, zoneUri);
        return new OrchestratorZoneResponse(zoneName, zone, connectionDetails);
    }

    public ResponseEntity<?> deleteZone(String zoneName) {
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone - deleting Name[" + zoneName + "]");
            IdentityZone zone = zoneProvisioning.retrieveByName(zoneName);
            IdentityZoneHolder.set(zone);
            if (publisher != null && zone != null) {
                publisher.publishEvent(new EntityDeletedEvent<>(zone, SecurityContextHolder.getContext().getAuthentication(), IdentityZoneHolder.getCurrentZoneId()));
                logger.debug("Zone - deleted id[" + zone.getId() + "]");
                return new ResponseEntity<>(ACCEPTED);
            } else {
                return new ResponseEntity<>(INTERNAL_SERVER_ERROR);
            }
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    private ConnectionDetails buildConnectionDetails(String zoneName, IdentityZone identityZone,
                                                            String zoneUri) {
        ConnectionDetails connectionDetails = new ConnectionDetails();
        connectionDetails.setUri(zoneUri);
        connectionDetails.setIssuerId(zoneUri + "/oauth/token");
        connectionDetails.setSubdomain(identityZone.getSubdomain());
        connectionDetails.setDashboardUri(uaaDashboardUri);
        OrchestratorZoneHeader zoneHeader = new OrchestratorZoneHeader(X_IDENTITY_ZONE_ID, identityZone.getId());
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

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }
}
