package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;

import static org.springframework.http.HttpStatus.OK;

@Controller
public class OpenIdConnectEndpoints {

    private final String issuer;
    private final IdentityZoneManager identityZoneManager;

    public OpenIdConnectEndpoints(
            final @Value("${issuer.uri}") String issuer,
            final IdentityZoneManager identityZoneManager
    ) {
        this.issuer = issuer;
        this.identityZoneManager = identityZoneManager;
    }

    @GetMapping(value = {
            "/.well-known/openid-configuration",
            "/oauth/token/.well-known/openid-configuration"
    })
    public ResponseEntity<OpenIdConfiguration> getOpenIdConfiguration(HttpServletRequest request) throws URISyntaxException {
        OpenIdConfiguration conf = new OpenIdConfiguration(getServerContextPath(request), getTokenEndpoint());
        return new ResponseEntity<>(conf, OK);
    }

    private String getServerContextPath(HttpServletRequest request) {
        //more robust implementation since we
        //adjust the context and servlet paths
        //when using zone paths /z/{subdomain}
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        StringBuilder base = new StringBuilder().append(scheme).append("://").append(serverName);
        if (("http".equals(scheme) && serverPort != 80) || ("https".equals(scheme) && serverPort != 443)) {
            base.append(':').append(serverPort);
        }
        base.append(contextPath);
        return base.toString();
    }

    private String getTokenEndpoint() throws URISyntaxException {
        return UaaTokenUtils.constructTokenEndpointUrl(issuer, identityZoneManager.getCurrentIdentityZone());
    }
}
