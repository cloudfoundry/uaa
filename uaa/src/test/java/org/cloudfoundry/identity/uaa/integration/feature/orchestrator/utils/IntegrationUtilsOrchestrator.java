package org.cloudfoundry.identity.uaa.integration.feature.orchestrator.utils;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

public class IntegrationUtilsOrchestrator {

    private static IdentityZone createOrchZone(RestTemplate client,
                                               String url,
                                               String id,
                                               String subdomain,
                                               boolean active) throws Throwable {
        OrchestratorZoneRequest orchestratorZoneRequest = new OrchestratorZoneRequest();
        orchestratorZoneRequest.setName(id);
        orchestratorZoneRequest.setParameters(new OrchestratorZone("adminsecret", subdomain));
        //Create orch zone
        client.postForEntity(url + "/orchestrator/zones", orchestratorZoneRequest, OrchestratorZoneResponse.class);
        //Get orch zone
        ResponseEntity<OrchestratorZoneResponse> orchestratorZone = client.getForEntity(url + "/orchestrator/zones?name=" + id, OrchestratorZoneResponse.class, id);
        //Retrieve Zone ID for Identity Zone from orch Header
        OrchestratorZoneResponse getZoneResponse = orchestratorZone.getBody();
        final String zoneId = getZoneResponse.getConnectionDetails().getZone().getHttpHeaderValue();
        //Retrieve
        ResponseEntity<IdentityZone> nativeZone = client.getForEntity(url + "/identity-zones/" + zoneId, IdentityZone.class, id);
        return nativeZone.getBody();
    }


    public static IdentityZone createOrchZone(RestTemplate client,
                                              String url,
                                              String id,
                                              String subdomain
                                                 ) throws Throwable {
        return createOrchZone(client, url, id, subdomain, true);
    }



}
