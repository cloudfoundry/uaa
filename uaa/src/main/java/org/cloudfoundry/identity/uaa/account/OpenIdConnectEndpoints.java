package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;

import static org.springframework.http.HttpStatus.OK;

@Controller
public class OpenIdConnectEndpoints {

    private String issuer;

    @RequestMapping(value = {"/.well-known/openid-configuration", "/oauth/token/.well-known/openid-configuration"})
    public ResponseEntity<OpenIdConfiguration> getOpenIdConfiguration(HttpServletRequest request) throws URISyntaxException {
        OpenIdConfiguration conf = new OpenIdConfiguration(getServerContextPath(request), getTokenEndpoint());
        return new ResponseEntity<>(conf, OK);
    }

    private String getServerContextPath(HttpServletRequest request) {
        StringBuffer requestURL = request.getRequestURL();
        return requestURL.substring(0, requestURL.length() - request.getServletPath().length());
    }

    public String getTokenEndpoint() throws URISyntaxException {
        return UaaTokenUtils.constructTokenEndpointUrl(issuer, IdentityZoneHolder.get());
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
