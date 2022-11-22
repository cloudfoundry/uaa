package org.cloudfoundry.identity.uaa.zone.model;

import lombok.Data;

@Data
public class ConnectionDetails {
    private String uri;
    private String dashboardUri;
    private String issuerId;
    private String subdomain;
    private ZoneHeader zone;
}
