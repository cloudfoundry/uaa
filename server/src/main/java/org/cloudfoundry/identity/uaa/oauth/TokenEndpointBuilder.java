package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;

import java.net.URISyntaxException;
import java.net.URL;

public class TokenEndpointBuilder {
    private final Log logger = LogFactory.getLog(getClass());
    private String issuer;

    public TokenEndpointBuilder(String issuerUrlBase) throws Exception {
        new URL(issuerUrlBase); // validate issuer url is valid
        this.issuer = issuerUrlBase;
    }

    public String getTokenEndpoint() {
        try {
            return UaaTokenUtils.constructTokenEndpointUrl(issuer);
        } catch (URISyntaxException e) {
            logger.error("Failed to get token endpoint for issuer " + issuer, e);
            throw new IllegalArgumentException(e);
        }
    }

    public String getIssuer() {
        return issuer;
    }
}
