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

    public String getClientRedirect(HttpServletRequest request, String redirectUri) {
        String clientId = request.getParameter(CLIENT_ID);
        logger.debug(String.format("Evaluating client logout redirect client_id:%s and redirect:%s", clientId, redirectUri));
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(redirectUri)) {
            return null;
        }
        Set<String> redirectUris = null;
        try {
            ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
            redirectUris = client.getRegisteredRedirectUri();
        } catch (NoSuchClientException x) {
            logger.debug(String.format("Unable to find client with ID:%s for logout redirect", clientId));
        }
        return UaaUrlUtils.findMatchingRedirectUri(redirectUris, redirectUri);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String url =  super.determineTargetUrl(request, response);
        String whiteListRedirect = UaaUrlUtils.findMatchingRedirectUri(getWhitelist(), url);
        boolean whitelisted = false;
        if (StringUtils.hasText(whiteListRedirect)) {
            url = whiteListRedirect;
            whitelisted = true;
        }
        String clientRedirectUri = getClientRedirect(request, url);
        if (StringUtils.hasText(clientRedirectUri)) {
            url = clientRedirectUri;
            whitelisted = true;
        }
        if (!whitelisted && getWhitelist()!=null) { //if we didn't find a matching URL, and whitelist is set to enforce (!=null)
            url = getDefaultTargetUrl();
        }
        logger.debug("Logout redirect[whitelisted:"+whitelisted+"; redirect:"+request.getParameter(getTargetUrlParameter())+"] returning:"+url);
        return url;
    }

}
