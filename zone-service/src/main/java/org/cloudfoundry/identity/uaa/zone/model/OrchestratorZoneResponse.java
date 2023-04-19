package org.cloudfoundry.identity.uaa.zone.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrchestratorZoneResponse {

    private String name;
    private ConnectionDetails connectionDetails;
    private String message;
    private String state;
}
