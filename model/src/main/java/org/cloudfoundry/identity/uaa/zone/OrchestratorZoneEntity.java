package org.cloudfoundry.identity.uaa.zone;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrchestratorZoneEntity {

    private Long id;
    private String orchestratorZoneName;
    private String identityZoneId;
    private String subdomain;
    private LocalDateTime created;
    private LocalDateTime lastModified;


}
