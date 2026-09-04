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

import java.util.Map;

@Controller
public class IntrospectEndpoint {
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    // RFC 7662 section 2.2: an inactive-token response MUST contain only "active": false
    // and SHOULD NOT include any other information about the token. IntrospectionClaims
    // has other fields (e.g. `revocable`, a primitive) that can't be suppressed via
    // @JsonInclude once populated, so the inactive case returns this minimal value instead.
    private static final Map<String, Object> INACTIVE_TOKEN_RESPONSE = Map.of("active", false);

    private final ResourceServerTokenServices resourceServerTokenServices;

    public IntrospectEndpoint(
            final @Qualifier("tokenServices") ResourceServerTokenServices resourceServerTokenServices) {
        this.resourceServerTokenServices = resourceServerTokenServices;
    }

    @PostMapping("/introspect")
    @ResponseBody
    public Object introspect(@RequestParam String token) {
        try {
            OAuth2AccessToken oAuth2AccessToken = resourceServerTokenServices.readAccessToken(token);
            if (oAuth2AccessToken.isExpired()) {
                return INACTIVE_TOKEN_RESPONSE;
            }
            resourceServerTokenServices.loadAuthentication(token);
            IntrospectionClaims introspectionClaims = UaaTokenUtils.getClaims(oAuth2AccessToken.getValue(), IntrospectionClaims.class);
            introspectionClaims.setActive(true);
            return introspectionClaims;
        } catch (InvalidTokenException _) {
            return INACTIVE_TOKEN_RESPONSE;
        }
    }

    @RequestMapping(value = "/introspect")
    @ResponseBody
    public IntrospectionClaims methodNotSupported(HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        throw new HttpRequestMethodNotSupportedException(request.getMethod());
    }
}
