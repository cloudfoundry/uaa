package org.cloudfoundry.identity.uaa.zone.model;

import lombok.Data;
import javax.validation.constraints.NotBlank;

@Data
public class OrchestratorZoneRequest {
    @NotBlank(message = org.cloudfoundry.identity.uaa.zone.OrchestratorZoneController.MANDATORY_VALIDATION_MESSAGE)
    private String name;
    private OrchestratorZone parameters;
}
