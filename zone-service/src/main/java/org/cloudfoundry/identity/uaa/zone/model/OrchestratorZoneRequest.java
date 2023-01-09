package org.cloudfoundry.identity.uaa.zone.model;

import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.ADMIN_CLIENT_CREDENTIALS_VALIDATION_MESSAGE;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.ADMIN_CLIENT_CREDENTIALS_VALIDATION_PATTERN;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.MANDATORY_VALIDATION_MESSAGE;

import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
public class OrchestratorZoneRequest {
    @NotBlank
    private String name;

    @Valid
    @NotNull(message = MANDATORY_VALIDATION_MESSAGE)
    private OrchestratorZone parameters;
}
