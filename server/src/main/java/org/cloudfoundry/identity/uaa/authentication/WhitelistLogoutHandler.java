package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;

public class WhitelistLogoutHandler extends SimpleUrlLogoutSuccessHandler {
    private static final Log logger = LogFactory.getLog(WhitelistLogoutHandler.class);

    private List<String> whitelist = null;

    private ClientDetailsService clientDetailsService;

    public WhitelistLogoutHandler(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    @Override
    protected String getTargetUrlParameter() {
        return super.getTargetUrlParameter();
    }

    @Override
    protected boolean isAlwaysUseDefaultTargetUrl() {
        return super.isAlwaysUseDefaultTargetUrl();
    }

    public String getDefaultTargetUrl1() {
        return super.getDefaultTargetUrl();
    }

    public List<String> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    private Set<String> getClientWhitelist(HttpServletRequest request) {
        String clientId = request.getParameter(CLIENT_ID);
        Set<String> redirectUris = null;

        if (StringUtils.hasText(clientId)) {
            try {
                ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
                redirectUris = client.getRegisteredRedirectUri();
            } catch (NoSuchClientException x) {
                logger.debug(String.format("Unable to find client with ID:%s for logout redirect", clientId));
            }
        }
        return redirectUris;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = super.determineTargetUrl(request, response);
        String defaultTargetUrl = getDefaultTargetUrl();
        if (targetUrl.equals(defaultTargetUrl)) {
            return targetUrl;
        }

        Set<String> clientWhitelist = getClientWhitelist(request);
        Set<String> combinedWhitelist = combineSets(whitelist, clientWhitelist);
        String whiteListRedirect = UaaUrlUtils.findMatchingRedirectUri(combinedWhitelist, targetUrl, defaultTargetUrl);

        return whiteListRedirect;
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
