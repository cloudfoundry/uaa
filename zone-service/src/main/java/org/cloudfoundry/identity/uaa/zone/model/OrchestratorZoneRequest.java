package org.cloudfoundry.identity.uaa.zone.model;

import lombok.Data;

@Data
public class OrchestratorZoneRequest {
    private String name;
    private OrchestratorZone parameters;
}
