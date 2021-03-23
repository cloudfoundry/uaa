package org.cloudfoundry.identity.uaa.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.oauth.beans.LegacyRedirectResolver;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;

public final class WhitelistLogoutHandler extends SimpleUrlLogoutSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(WhitelistLogoutHandler.class);

    private List<String> whitelist = null;

    private MultitenantClientServices clientDetailsService;

    private RedirectResolver redirectResolver;


    public WhitelistLogoutHandler(List<String> whitelist) {
        this.whitelist = whitelist;
        this.redirectResolver = new LegacyRedirectResolver();
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

    private Set<String> getClientWhitelist(ClientDetails client) {
        if(client != null) {
            return client.getRegisteredRedirectUri();
        }
        return null;
    }
    
    private ClientDetails getClient(HttpServletRequest request) {
        String clientId = request.getParameter(CLIENT_ID);
        ClientDetails client = null;
        if (StringUtils.hasText(clientId)) {
            try {
                client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
            } catch (NoSuchClientException x) {
                logger.debug(String.format("Unable to find client with ID:%s for logout redirect", clientId));
            }
        }
        return client;


    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = super.determineTargetUrl(request, response);

        if(isInternalRedirect(targetUrl, request)) {
            return targetUrl;
        }

        String defaultTargetUrl = getDefaultTargetUrl();
        if (targetUrl.equals(defaultTargetUrl)) {
            return targetUrl;
        }
        ClientDetails client = getClient(request);
        String whiteListRedirect;
        try{
            whiteListRedirect = redirectResolver.resolveRedirect(targetUrl, client);
        } catch (OAuth2Exception | NullPointerException e){
            logger.info(e.getMessage());
            whiteListRedirect = findMatchingRedirectUri(whitelist, targetUrl, defaultTargetUrl);
        }

        return whiteListRedirect;
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
