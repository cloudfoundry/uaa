package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.IntrospectionClaims;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class IntrospectEndpoint {
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final ResourceServerTokenServices resourceServerTokenServices;

    public IntrospectEndpoint(
            final @Qualifier("tokenServices") ResourceServerTokenServices resourceServerTokenServices) {
        this.resourceServerTokenServices = resourceServerTokenServices;
    }

    @PostMapping("/introspect")
    @ResponseBody
    public IntrospectionClaims introspect(@RequestParam String token) {
        IntrospectionClaims introspectionClaims = new IntrospectionClaims();

        try {
            OAuth2AccessToken oAuth2AccessToken = resourceServerTokenServices.readAccessToken(token);
            if (oAuth2AccessToken.isExpired()) {
                introspectionClaims.setActive(false);
                return introspectionClaims;
            }
            resourceServerTokenServices.loadAuthentication(token);
            introspectionClaims = UaaTokenUtils.getClaims(oAuth2AccessToken.getValue(), IntrospectionClaims.class);
            introspectionClaims.setActive(true);
        } catch (InvalidTokenException e) {
            introspectionClaims.setActive(false);
            return introspectionClaims;
        }

        return introspectionClaims;
    }

    @RequestMapping(value = "/introspect")
    @ResponseBody
    public IntrospectionClaims methodNotSupported(HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        throw new HttpRequestMethodNotSupportedException(request.getMethod());
    }
}
