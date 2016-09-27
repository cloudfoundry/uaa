/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Controller which decodes access tokens for clients who are not able to do so
 * (or where opaque token values are used).
 *
 * @author Luke Taylor
 * @author Joel D'sa
 */
@Controller
public class CheckTokenEndpoint implements InitializingBean {

    private ResourceServerTokenServices resourceServerTokenServices;
    protected final Log logger = LogFactory.getLog(getClass());
    private WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();
    public void setTokenServices(ResourceServerTokenServices resourceServerTokenServices) {
        this.resourceServerTokenServices = resourceServerTokenServices;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(resourceServerTokenServices, "tokenServices must be set");
    }

    @RequestMapping(value = "/check_token")
    @ResponseBody
    public Claims checkToken(@RequestParam("token") String value, @RequestParam(name = "scopes", required = false, defaultValue = "") List<String> scopes) {

        OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
        if (token == null) {
            throw new InvalidTokenException("Token was not recognised");
        }

        if (token.isExpired()) {
            throw new InvalidTokenException("Token has expired");
        }

        try {
            resourceServerTokenServices.loadAuthentication(value);
        } catch (AuthenticationException x) {
            throw new InvalidTokenException((x.getMessage()));
        }

        Claims response = getClaimsForToken(token.getValue());

        List<String> claimScopes = response.getScope().stream().map(String::toLowerCase).collect(Collectors.toList());

        List<String> missingScopes = new ArrayList<>();
        for(String expectedScope : scopes) {
            if (!claimScopes.contains(expectedScope.toLowerCase())) {
                missingScopes.add(expectedScope);
            }
        }

        if (!missingScopes.isEmpty()) {
            throw new InvalidScopeException("Some requested scopes are missing: " + String.join(",", missingScopes));
        }

        return response;
    }

    private Claims getClaimsForToken(String token) {
        Jwt tokenJwt;
        try {
            tokenJwt = JwtHelper.decode(token);
        } catch (Throwable t) {
            throw new InvalidTokenException("Invalid token (could not decode): " + token);
        }

        Claims claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), Claims.class);
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot read token claims", e);
        }

        return claims;
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
        // This isn't an oauth resource, so we don't want to send an
        // unauthorized code here.
        // The client has already authenticated successfully with basic auth and
        // should just
        // get back the invalid token error.
        InvalidTokenException e400 = new InvalidTokenException(e.getMessage()) {
            @Override
            public int getHttpErrorCode() {
                return 400;
            }
        };
        return exceptionTranslator.translate(e400);
    }

    @ExceptionHandler(InvalidScopeException.class)
    public ResponseEntity<OAuth2Exception> handleInvalidScopeException(Exception e) throws Exception {
        logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
        return exceptionTranslator.translate(e);
    }

}
