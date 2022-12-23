package org.cloudfoundry.identity.uaa.zone.model;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AllArgsConstructor;
import lombok.Data;
@Data
@AllArgsConstructor
@JsonInclude(Include.NON_NULL)
public class OrchestratorErrorResponse {
    private String message;
}