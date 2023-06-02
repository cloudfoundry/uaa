package org.cloudfoundry.identity.uaa.zone.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrchestratorZoneHeader {

    @JsonProperty("http-header-name")
    private String httpHeaderName;
    @JsonProperty("http-header-value")
    private String httpHeaderValue;

}
