package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.advice.HttpMethodNotSupportedAdvice;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTargetException;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.TokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.core.type.TypeReference;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.springframework.util.StringUtils.hasText;

@Controller
@RequestMapping(value = {"/oauth/token", "/oauth/mtls/token"}) //used simply because TokenEndpoint wont match /oauth/token/alias/saml-entity-id
public class UaaTokenEndpoint extends TokenEndpoint {

    private final boolean allowQueryString;

    public UaaTokenEndpoint(
            final @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final @Qualifier("oauth2RequestValidator") OAuth2RequestValidator oAuth2RequestValidator,
            final @Qualifier("oauth2TokenGranter") TokenGranter tokenGranter,
            final @Qualifier("allowQueryStringForTokens") Boolean allowQueryStringForTokens
    ) {
        this.setOAuth2RequestFactory(oAuth2RequestFactory);
        this.setClientDetailsService(clientDetailsService);
        this.setOAuth2RequestValidator(oAuth2RequestValidator);
        this.setTokenGranter(tokenGranter);

        this.allowQueryString = Boolean.TRUE.equals(Optional
                .ofNullable(allowQueryStringForTokens)
                .orElse(Boolean.TRUE));

        if (allowQueryString) {
            super.setAllowedRequestMethods(new HashSet<>(Arrays.asList(HttpMethod.GET, HttpMethod.POST)));
        } else {
            super.setAllowedRequestMethods(Collections.singleton(HttpMethod.POST));
        }
    }

    @GetMapping("**")
    public ResponseEntity<OAuth2AccessToken> doDelegateGet(Principal principal,
            @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        rejectNonWorkloadGrantAtMtlsEndpoint(currentRequest(), parameters);
        enforceResourceIndicator(currentRequest(), principal);
        return getAccessToken(principal, parameters);
    }

    @PostMapping("**")
    public ResponseEntity<OAuth2AccessToken> doDelegatePost(Principal principal,
            @RequestParam Map<String, String> parameters,
            HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        if (hasText(request.getQueryString()) && !this.allowQueryString) {
            logger.debug("Call to /oauth/token contains a query string. Aborting.");
            throw new HttpRequestMethodNotSupportedException("POST");
        }
        rejectNonWorkloadGrantAtMtlsEndpoint(request, parameters);
        enforceResourceIndicator(request, principal);
        return postAccessToken(principal, parameters);
    }

    /**
     * The mTLS token endpoint exists to exchange a workload's X.509 identity for a token about that
     * workload, so it issues {@code client_credentials} tokens only.
     *
     * <p>Every other grant was reachable here: the chain installs
     * {@code BackwardsCompatibleTokenEndpointAuthenticationFilter} exactly as {@code /oauth/token}
     * does. A certificate-authenticated client whose {@code authorized_grant_types} include
     * {@code password} could therefore exchange a username and password for a user token at this
     * endpoint, and {@code MtlsClaimsEnhancer} would stamp it with {@code cnf.x5t#S256} -- the RFC 8705
     * section 3 confirmation claim, which tells a resource server "the presenter holds this
     * certificate". The result was a single token asserting two unrelated identities: the app
     * instance's (via {@code cnf} and the certificate-derived claims) and the user's (via
     * {@code user_id}/{@code user_name}/{@code email}), with nothing marking which claim came from
     * which credential. The refresh token it returned was usable here too.
     *
     * <p>Rejected as {@code invalid_grant} rather than silently stripping {@code cnf}, so an operator
     * who configured a grant that cannot work here is told, instead of receiving a token that quietly
     * means less than it appears to.
     */
    private static void rejectNonWorkloadGrantAtMtlsEndpoint(
            HttpServletRequest request, Map<String, String> parameters) {
        if (request == null || !RawPeerCertificateCaptureFilter.isMtlsTokenPath(request.getServletPath())) {
            return;
        }
        String grantType = parameters == null ? null : parameters.get("grant_type");
        if (!GRANT_TYPE_CLIENT_CREDENTIALS.equals(grantType)) {
            // Deliberately does not echo the submitted grant_type back into the response.
            throw new InvalidGrantException(
                    "the mTLS token endpoint only issues client_credentials tokens");
        }
    }

    /**
     * RFC 8707 section 2: a client may request a specific {@code resource} (audience) at the mTLS
     * token endpoint, but only one drawn from a per-client allow-list -- {@code
     * tls-client-auth-allowed-resources}, validated for shape at registration by {@code
     * ClientAdminEndpointsValidator} -- since without curation any client could name an arbitrary
     * audience for itself, the same forgery shape already closed for {@code
     * tls-client-auth-sub-template}/{@code -aud-templates}. Runs before the grant, so an
     * unauthorized or malformed resource never reaches token issuance.
     *
     * <p>This is the primary check, not the only one. {@code MtlsClaimsEnhancer} re-checks the
     * allow-list (and the grant type) itself rather than trusting that a {@code resource} value
     * reaching token issuance was validated here: a request can reach the granter without passing
     * through these delegates (Spring also maps the inherited {@code TokenEndpoint} handlers beneath
     * the type-level paths), and {@code MtlsEndpointAvailabilityFilter} closing that route should not
     * be what the guarantee depends on. That second check is deliberate -- not redundant.
     */
    private void enforceResourceIndicator(HttpServletRequest request, Principal principal) {
        if (request == null || !RawPeerCertificateCaptureFilter.isMtlsTokenPath(request.getServletPath())) {
            return;
        }
        String[] resources = request.getParameterValues(TlsClientAuthConfiguration.RESOURCE_PARAMETER);
        if (resources == null || resources.length == 0) {
            return;
        }
        if (resources.length > 1) {
            throw new InvalidTargetException(
                    "the mTLS token endpoint does not support more than one resource parameter");
        }
        String resource = resources[0];
        requireValidResourceSyntax(resource);
        if (!(principal instanceof Authentication authentication) || !authentication.isAuthenticated()) {
            // Not this method's job to raise the missing-authentication error; postAccessToken /
            // getAccessToken already does, immediately after this call returns.
            return;
        }
        String clientId = getClientId(principal);
        if (!allowedResourcesFor(clientId).contains(resource)) {
            // Deliberately does not echo the submitted resource value back into the response --
            // same reasoning as rejectNonWorkloadGrantAtMtlsEndpoint's grant_type.
            throw new InvalidTargetException(
                    "client_id=" + clientId + " is not authorized to request the given resource");
        }
    }

    /**
     * RFC 8707 section 2: "the resource parameter... MUST be an absolute URI... MUST NOT include a
     * fragment component."
     */
    private static void requireValidResourceSyntax(String resource) {
        URI uri;
        try {
            uri = new URI(resource);
        } catch (URISyntaxException e) {
            throw new InvalidTargetException("resource must be a valid absolute URI with no fragment");
        }
        if (!uri.isAbsolute() || uri.getFragment() != null) {
            throw new InvalidTargetException("resource must be a valid absolute URI with no fragment");
        }
    }

    /**
     * The client's {@code tls-client-auth-allowed-resources}: the typed field if one is set, otherwise
     * {@code additionalInformation} -- the same two-step lookup {@code MtlsClaimsEnhancer} uses for the
     * rest of this configuration. Clients loaded from the database carry their configuration in
     * {@code additionalInformation}, so that is the path that matters in practice. Returns an empty list (authorizing nothing) rather than throwing when the
     * client cannot be loaded or the value cannot be parsed, so a lookup failure fails closed.
     */
    private List<String> allowedResourcesFor(String clientId) {
        ClientDetails client;
        try {
            client = getClientDetailsService().loadClientByClientId(clientId);
        } catch (Exception e) {
            return List.of();
        }
        if (client instanceof UaaClientDetails uaaClient) {
            TlsClientAuthConfiguration typed = uaaClient.getTlsClientAuthConfiguration();
            if (typed != null && typed.getAllowedResources() != null) {
                return typed.getAllowedResources();
            }
        }
        Object raw = client.getAdditionalInformation() == null ? null
                : client.getAdditionalInformation().get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES);
        try {
            if (raw instanceof String json) {
                return JsonUtils.readValue(json, new TypeReference<List<String>>() {});
            } else if (raw != null) {
                return JsonUtils.readValue(JsonUtils.writeValueAsString(raw), new TypeReference<List<String>>() {});
            }
        } catch (Exception e) {
            return List.of();
        }
        return List.of();
    }

    /**
     * The servlet request for the call in progress, or {@code null} when there is no request context
     * -- which is the case when {@code doDelegateGet} is invoked directly from a unit test. Used
     * instead of adding an {@code HttpServletRequest} parameter to {@code doDelegateGet}, whose
     * signature existing tests call directly.
     */
    private static HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servletAttributes
                ? servletAttributes.getRequest()
                : null;
    }

    @RequestMapping(value = "**")
    public void methodsNotAllowed(HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        throw new HttpRequestMethodNotSupportedException(request.getMethod());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @Override
    public ResponseEntity<OAuth2Exception> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
        return new HttpMethodNotSupportedAdvice().handleMethodNotSupportedException(e);
    }

    @ExceptionHandler(Exception.class)
    @Override
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.error("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage(), e);
        return getExceptionTranslator().translate(e);
    }

    /**
     * This is a NOOP
     * This class will control which request methods are allowed,
     * based on allowQueryStringForTokens
     */
    @Override
    public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
    }
}
