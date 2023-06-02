package org.cloudfoundry.identity.uaa.zone.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class ConnectionDetails {
    @JsonProperty("uri")
    private String uri;
    @JsonProperty("dashboardUrl")
    private String dashboardUri;
    @JsonProperty("issuerId")
    private String issuerId;
    @JsonProperty("subdomain")
    private String subdomain;
    @JsonProperty("zone")
    private OrchestratorZoneHeader zone;
}
