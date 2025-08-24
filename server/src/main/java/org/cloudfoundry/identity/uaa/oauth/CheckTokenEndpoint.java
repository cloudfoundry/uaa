package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.error.ParameterParsingException;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultWebResponseExceptionTranslator;
import org.cloudfoundry.identity.uaa.oauth.provider.error.WebResponseExceptionTranslator;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static org.springframework.util.StringUtils.commaDelimitedListToSet;
import static org.springframework.util.StringUtils.hasText;

/**
 * Controller which decodes access tokens for clients who are not able to do so
 * (or where opaque token values are used).
 */
@Controller
public class CheckTokenEndpoint implements InitializingBean {

    //Copy of the value from org.apache.Globals.PARAMETER_PARSE_FAILED_ATTR
    private static final String PARAMETER_PARSE_FAILED_ATTR = "org.apache.catalina.parameter_parse_failed";
    private static final String HANDLING_ERROR = "Handling error: {}, {}";

    private final ResourceServerTokenServices resourceServerTokenServices;
    private final TimeService timeService;

    protected final Logger logger = LoggerFactory.getLogger(getClass());
    private WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();

    public CheckTokenEndpoint(
            final @Qualifier("tokenServices") ResourceServerTokenServices resourceServerTokenServices,
            final @Qualifier("timeService") TimeService timeService) {
        this.resourceServerTokenServices = resourceServerTokenServices;
        this.timeService = timeService;
    }

    private Boolean allowQueryString;

    public boolean isAllowQueryString() {
        return allowQueryString == null ? true : allowQueryString;
    }

    @Autowired
    @Qualifier("allowQueryStringForTokens")
    public void setAllowQueryString(boolean allowQueryString) {
        this.allowQueryString = allowQueryString;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(resourceServerTokenServices, "tokenServices must be set");
    }

    @PostMapping("/check_token")
    @ResponseBody
    @Deprecated
    public Claims checkToken(@RequestParam(name = "token", required = false, defaultValue = "") String value,
                             @RequestParam(required = false, defaultValue = "") List<String> scopes,
                             HttpServletRequest request) throws HttpRequestMethodNotSupportedException {

        if (!hadParsedAllArgs(request)) {
            throw new ParameterParsingException();
        }

        if (!hasText(value)) {
            throw new InvalidTokenException("Token parameter must be set");
        }

        if (hasText(request.getQueryString()) && !isAllowQueryString()) {
            logger.debug("Call to /oauth/check_token contains a query string. Aborting.");
            throw new HttpRequestMethodNotSupportedException("POST");
        }

        OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
        if (token == null) {
            throw new InvalidTokenException("Token was not recognised");
        }

        if (token.getExpiration() != null && token.getExpiration().before(timeService.getCurrentDate())) {
            throw new InvalidTokenException("Token has expired");
        }

        try {
            resourceServerTokenServices.loadAuthentication(value);
        } catch (AuthenticationException x) {
            throw new InvalidTokenException((x.getMessage()));
        }

        Claims response = UaaTokenUtils.getClaimsFromTokenString(token.getValue());

        List<String> claimScopes = Optional.ofNullable(response.getScope()).orElse(emptyList()).stream()
                .map(String::toLowerCase)
                .toList();

        List<String> missingScopes = new ArrayList<>();
        for (String expectedScope : scopes) {
            if (!claimScopes.contains(expectedScope.toLowerCase())) {
                missingScopes.add(expectedScope);
            }
        }

        if (!missingScopes.isEmpty()) {
            throw new InvalidScopeException("Some requested scopes are missing: " + String.join(",", missingScopes));
        }

        return response;
    }

    private boolean hadParsedAllArgs(HttpServletRequest request) {
        return request.getAttribute(PARAMETER_PARSE_FAILED_ATTR) == null;
    }

    @RequestMapping(value = "/check_token")
    @ResponseBody
    @Deprecated
    public Claims checkToken(HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        if (isAllowQueryString()) {
            String token = request.getParameter("token");
            String scope = request.getParameter("scope");
            return
                    checkToken(
                            token,
                            hasText(scope) ? new LinkedList<>(commaDelimitedListToSet(scope)) : emptyList(),
                            request
                    );
        } else {
            throw new HttpRequestMethodNotSupportedException(request.getMethod());
        }
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.info(HANDLING_ERROR, e.getClass().getSimpleName(), e.getMessage());
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
        logger.info(HANDLING_ERROR, e.getClass().getSimpleName(), e.getMessage());
        return exceptionTranslator.translate(e);
    }

    @ExceptionHandler(UaaException.class)
    public ResponseEntity<UaaException> handleInvalidScopeSTUFF(UaaException e) {
        logger.info(HANDLING_ERROR, e.getClass().getSimpleName(), e.getMessage());
        return new ResponseEntity<>(e, HttpStatus.valueOf(e.getHttpStatus()));
    }
}
