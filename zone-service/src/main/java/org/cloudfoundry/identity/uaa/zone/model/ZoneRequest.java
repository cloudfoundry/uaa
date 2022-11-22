package org.cloudfoundry.identity.uaa.zone.model;

import lombok.Data;

@Data
public class ZoneRequest {
    private String name;
    private Zone parameters;
}
