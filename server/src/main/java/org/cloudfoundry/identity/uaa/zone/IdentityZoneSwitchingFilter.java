package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.web.HttpHeadersFilterRequestWrapper;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.ZONES_ZONE_ID_PREFIX;
import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.getZoneSwitchingScopes;

/**
 * If the X-Identity-Zone-Id header is set and the user has a scope
 * of zones.&lt;id&gt;.admin, this filter switches the IdentityZone in the IdentityZoneHolder
 * to the one in the header.
 */
public class IdentityZoneSwitchingFilter extends OncePerRequestFilter {

    public IdentityZoneSwitchingFilter(IdentityZoneProvisioning dao) {
        super();
        this.dao = dao;
    }

    private final IdentityZoneProvisioning dao;
    public static final String HEADER = "X-Identity-Zone-Id";
    public static final String SUBDOMAIN_HEADER = "X-Identity-Zone-Subdomain";
    public static final List<String> zoneScopestoNotStripPrefix = List.of("admin", "read");

    protected OAuth2Authentication getAuthenticationForZone(String identityZoneId, HttpServletRequest servletRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2Authentication oa)) {
            return null;
        }

        Object oaDetails = oa.getDetails();

        //strip client scopes
        OAuth2Request request = oa.getOAuth2Request();
        Collection<String> requestAuthorities = UaaStringUtils.getStringsFromAuthorities(request.getAuthorities());
        Set<String> clientScopes = new HashSet<>();
        Set<String> clientAuthorities = new HashSet<>();
        for (String s : getZoneSwitchingScopes(identityZoneId)) {
            String scope = stripPrefix(s, identityZoneId);
            if (request.getScope().contains(s)) {
                clientScopes.add(scope);
            }
            if (requestAuthorities.contains(s)) {
                clientAuthorities.add(scope);
            }
        }
        request = new OAuth2Request(
                request.getRequestParameters(),
                request.getClientId(),
                UaaStringUtils.getAuthoritiesFromStrings(clientAuthorities),
                request.isApproved(),
                clientScopes,
                request.getResourceIds(),
                request.getRedirectUri(),
                request.getResponseTypes(),
                request.getExtensions()
        );

        UaaAuthentication userAuthentication = (UaaAuthentication) oa.getUserAuthentication();
        if (userAuthentication != null) {
            userAuthentication = new UaaAuthentication(
                    userAuthentication.getPrincipal(),
                    null,
                    UaaStringUtils.getAuthoritiesFromStrings(clientScopes),
                    new UaaAuthenticationDetails(servletRequest),
                    true, userAuthentication.getAuthenticatedTime());
        }
        oa = new UaaOauth2Authentication(((UaaOauth2Authentication) oa).getTokenValue(), IdentityZoneHolder.get().getId(), request, userAuthentication);
        oa.setDetails(oaDetails);
        return oa;
    }

    protected String stripPrefix(String s, String identityZoneId) {
        if (!StringUtils.hasText(s)) {
            return s;
        }
        //dont touch the zones.{zone.id}.admin scope
        String replace = ZONES_ZONE_ID_PREFIX + identityZoneId + ".";
        for (String scope : zoneScopestoNotStripPrefix) {
            if (s.equals(replace + scope)) {
                return s;
            }
        }

        //replace zones.<id>.
        if (s.startsWith(replace)) {
            return s.substring(replace.length());
        }
        return s;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String identityZoneIdFromHeader = request.getHeader(HEADER);
        String identityZoneSubDomainFromHeader = request.getHeader(SUBDOMAIN_HEADER);

        if (UaaStringUtils.isEmpty(identityZoneIdFromHeader) && UaaStringUtils.isEmpty(identityZoneSubDomainFromHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        IdentityZone identityZone = validateIdentityZone(identityZoneIdFromHeader, identityZoneSubDomainFromHeader);
        if (identityZone == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Identity zone with id/subdomain " + identityZoneIdFromHeader + "/" + identityZoneSubDomainFromHeader + " does not exist");
            return;
        }

        if (identityZone.isUaa()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Superfluous attempt to switch to UAA(system) zone. Header[" + HEADER + "] will be ignored");
            }
            filterChain.doFilter(new HttpHeadersFilterRequestWrapper(Arrays.asList(HEADER),request), response);
            return;
        }

        String identityZoneId = identityZone.getId();
        OAuth2Authentication oAuth2Authentication = getAuthenticationForZone(identityZoneId, request);
        if (IdentityZoneHolder.isUaa() && oAuth2Authentication != null && !oAuth2Authentication.getOAuth2Request().getScope().isEmpty()) {
            SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication);
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "User is not authorized to switch to IdentityZone with id " + identityZoneId);
            return;
        }

        IdentityZone originalIdentityZone = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(identityZone);
            filterChain.doFilter(request, response);
        } finally {
            IdentityZoneHolder.set(originalIdentityZone);
        }
    }

    private IdentityZone validateIdentityZone(String identityZoneId, String identityZoneSubDomain) {
        IdentityZone identityZone = null;

        try {
            if (UaaStringUtils.isEmpty(identityZoneId)) {
                identityZone = dao.retrieveBySubdomain(identityZoneSubDomain);
            } else {
                identityZone = dao.retrieve(identityZoneId);
            }
        } catch (ZoneDoesNotExistsException | EmptyResultDataAccessException ignored) {
        }
        return identityZone;
    }
}
