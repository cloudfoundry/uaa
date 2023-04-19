package org.cloudfoundry.identity.uaa.zone.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrchestratorZoneResponse {

    private String name;
    // Per orchestrator documentation, parameters field is mandatory only if service supports update.
    // However, current orchestrator implementation depends on parameters to be present and set to NULL
    // for services that do not support update.
    private OrchestratorZone parameters;
    private ConnectionDetails connectionDetails;
    private String message;
    private String state;
}
