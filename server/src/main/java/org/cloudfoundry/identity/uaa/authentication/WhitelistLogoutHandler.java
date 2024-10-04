package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.SignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildIdTokenValidator;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;

public final class WhitelistLogoutHandler extends SimpleUrlLogoutSuccessHandler {
    final String OPEN_ID_TOKEN_HINT = "id_token_hint";
    private static final Logger logger = LoggerFactory.getLogger(WhitelistLogoutHandler.class);

    private List<String> whitelist = null;

    private MultitenantClientServices clientDetailsService;
    private KeyInfoService keyInfoService;

    public WhitelistLogoutHandler(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    @Override
    protected boolean isAlwaysUseDefaultTargetUrl() {
        return false;
    }

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    public MultitenantClientServices getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(MultitenantClientServices clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setKeyInfoService(KeyInfoService keyInfoService) {
        this.keyInfoService = keyInfoService;
    }

    private Set<String> getClientWhitelist(HttpServletRequest request) {
        String clientId = null;
        String idToken = request.getParameter(OPEN_ID_TOKEN_HINT);
        Set<String> redirectUris = null;

        if (idToken != null) {
            try {
                Map<String, KeyInfo> keys = keyInfoService.getKeys();
                List<SignatureVerifier> signatureVerifiers = keys.values().stream().map(i -> i.getVerifier()).collect(Collectors.toList());
                JwtTokenSignedByThisUAA jwtToken =buildIdTokenValidator(idToken, new ChainedSignatureVerifier(signatureVerifiers), keyInfoService);
                clientId = (String) jwtToken.getClaims().get(ClaimConstants.AZP);
            } catch (InvalidTokenException e) {
                logger.debug("Invalid token (could not verify signature)");
            }
        } else {
            clientId = request.getParameter(CLIENT_ID);
        }

        if (StringUtils.hasText(clientId)) {
            try {
                ClientDetails client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
                redirectUris = client.getRegisteredRedirectUri();
            } catch (NoSuchClientException x) {
                logger.debug(String.format("Unable to find client with ID:%s for logout redirect", clientId));
            }
        }
        return redirectUris;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = request.getParameter("post_logout_redirect_uri");

        if (targetUrl == null) {
            targetUrl = super.determineTargetUrl(request, response);
        }

        if(isInternalRedirect(targetUrl, request)) {
            return targetUrl;
        }

        String defaultTargetUrl = getDefaultTargetUrl();
        if (targetUrl.equals(defaultTargetUrl)) {
            return targetUrl;
        }

        Set<String> clientWhitelist = getClientWhitelist(request);
        Set<String> combinedWhitelist = combineSets(whitelist, clientWhitelist);

        return findMatchingRedirectUri(combinedWhitelist, targetUrl, defaultTargetUrl);
    }

    private boolean isInternalRedirect(String targetUrl, HttpServletRequest request) {
        String serverUrl = request.getRequestURL().toString().replaceAll("/logout\\.do$", "/");
        return targetUrl.startsWith(serverUrl);
    }

    private static <T> Set<T> combineSets(Collection<T>... sets) {
        Set<T> combined = null;
        for(Collection<T> set : sets) {
            if(set != null) {
                if(combined == null) { combined = new HashSet<>(set); }
                else { combined.addAll(set); }
            }
        }
        return combined;
    }
}
