package org.cloudfoundry.identity.uaa.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.IntrospectionClaims;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class IntrospectEndpoint {
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final ResourceServerTokenServices resourceServerTokenServices;

    public IntrospectEndpoint(
            final @Qualifier("tokenServices") ResourceServerTokenServices resourceServerTokenServices) {
        this.resourceServerTokenServices = resourceServerTokenServices;
    }

    @RequestMapping(value = "/introspect", method = POST)
    @ResponseBody
    public IntrospectionClaims introspect(@RequestParam("token") String token) {
        IntrospectionClaims introspectionClaims = new IntrospectionClaims();

        try {
            OAuth2AccessToken oAuth2AccessToken = resourceServerTokenServices.readAccessToken(token);
            if (oAuth2AccessToken.isExpired()) {
                introspectionClaims.setActive(false);
                return introspectionClaims;
            }
            resourceServerTokenServices.loadAuthentication(token);
            introspectionClaims = getClaimsForToken(oAuth2AccessToken.getValue());
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


    private IntrospectionClaims getClaimsForToken(String token) {
        org.springframework.security.jwt.Jwt tokenJwt;
        tokenJwt = JwtHelper.decode(token);

        IntrospectionClaims claims;
        try {
            // we assume token.getClaims is never null due to previously parsing token when verifying the token
            claims = JsonUtils.readValue(tokenJwt.getClaims(), IntrospectionClaims.class);
        } catch (JsonUtils.JsonUtilException e) {
            logger.error("Can't parse introspection claims in token. Is it a valid JSON?");
            throw new InvalidTokenException("Cannot read token claims", e);
        }

        return claims;
    }
}
