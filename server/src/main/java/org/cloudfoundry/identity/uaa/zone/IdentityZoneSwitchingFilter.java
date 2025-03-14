package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.ZONES_ZONE_ID_PREFIX;
import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.getZoneSwitchingScopes;
import static org.springframework.util.StringUtils.hasText;

/**
 * If the X-Identity-Zone-Id header is set and the user has a scope
 * of zones.&lt;id&gt;.admin, this filter switches the IdentityZone in the IdentityZoneHolder
 * to the one in the header.
 */
public class IdentityZoneSwitchingFilter extends OncePerRequestFilter {

    @Autowired
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
        if (!hasText(s)) {
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

        ZoneSwitchDecision decision = new ZoneSwitchDecision(request);

        if (!decision.hasZoneSwitch()) {
            filterChain.doFilter(request, response);
            return;
        }

        IdentityZone identityZone = validateIdentityZone(decision.zoneId, decision.subdomain);
        if (identityZone == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Identity zone with id/subdomain " + decision.zoneId + "/" + decision.subdomain + " does not exist");
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

    private static boolean containsZoneSwitchHeader(HttpServletRequest request) {
        List<String> headers = Collections.list(request.getHeaderNames());
        return headers.contains(HEADER) || headers.contains(SUBDOMAIN_HEADER);
    }

    private IdentityZone validateIdentityZone(String identityZoneId, String identityZoneSubDomain) {
        IdentityZone identityZone = null;

        try {
            if (StringUtils.isEmpty(identityZoneId)) {
                identityZone = dao.retrieveBySubdomain(identityZoneSubDomain);
            } else {
                identityZone = dao.retrieve(identityZoneId);
            }
        } catch (ZoneDoesNotExistsException | EmptyResultDataAccessException ignored) {
        }
        return identityZone;
    }

    private record ZoneSwitchDecision(boolean headerPresent, String zoneId, String subdomain) {
        public ZoneSwitchDecision(HttpServletRequest request) {
            this(
                    containsZoneSwitchHeader(request),
                    request.getHeader(HEADER),
                    request.getHeader(SUBDOMAIN_HEADER)
            );
        }

        public boolean hasZoneSwitch() {
            if (this.headerPresent) {
                if (hasText(this.zoneId)) {
                    return !IdentityZone.getUaa().getId().equals(this.zoneId);
                } else {
                    return hasText(this.subdomain);
                }
            }
            return false;
        }
    }
}
