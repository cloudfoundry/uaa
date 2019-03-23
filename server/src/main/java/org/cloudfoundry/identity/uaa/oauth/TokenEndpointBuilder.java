package org.cloudfoundry.identity.uaa.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;

import java.net.URISyntaxException;
import java.net.URL;

public class TokenEndpointBuilder {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private String issuer;

    public TokenEndpointBuilder(String issuerUrlBase) throws Exception {
        setIssuer(issuerUrlBase);
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

    public void setIssuer(String issuer) throws Exception {
        new URL(issuer); // validate issuer url is valid
        this.issuer = issuer;
    }
}
