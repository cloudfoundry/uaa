package org.cloudfoundry.identity.uaa.zone.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrchestratorZoneResponse {

    @JsonProperty("name")
    private String name;
    // Per orchestrator documentation, parameters field is mandatory only if service supports update.
    // However, current orchestrator implementation depends on parameters to be present and set to NULL
    // for services that do not support update.
    @JsonProperty("parameters")
    private OrchestratorZone parameters;
    @JsonProperty("connectionDetails")
    private ConnectionDetails connectionDetails;
    @JsonProperty("message")
    private String message;
    @JsonProperty("state")
    private String state;
}
