package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class WhitelistLogoutHandler extends SimpleUrlLogoutSuccessHandler {
    private static final Log logger = LogFactory.getLog(WhitelistLogoutHandler.class);

    private List<String> whitelist = null;

    public WhitelistLogoutHandler(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    public List<String> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String url =  super.determineTargetUrl(request, response);
        boolean whitelisted = false;
        if (whitelist!=null) {
            for (String s : whitelist) {
                if (url.equals(s)) {
                    whitelisted = true;
                    break;
                }
            }
            if (!whitelisted) {
                url = getDefaultTargetUrl();
            }
        }
        logger.debug("Logout redirect[whitelisted:"+whitelisted+"; redirect:"+request.getParameter(getTargetUrlParameter())+"] returning:"+url);
        return url;

    }
}
