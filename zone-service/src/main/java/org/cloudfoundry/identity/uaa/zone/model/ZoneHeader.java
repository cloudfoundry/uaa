package org.cloudfoundry.identity.uaa.zone.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ZoneHeader {

    private String httpHeaderName;
    private String httpHeaderValue;

}
