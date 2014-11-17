package org.cloudfoundry.identity.uaa.zone;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;

public class IdentityZoneResolvingFilter extends OncePerRequestFilter {

    private IdentityZoneProvisioning dao;

    private String uaaHostname;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        IdentityZone identityZone = null;
        String hostname = request.getServerName();
        String subdomain = getSubdomain(hostname);
        if (subdomain != null) {
            try {
                identityZone = dao.retrieveBySubdomain(subdomain);
            } catch (Exception ex) {
            }
        }
        if (identityZone == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Cannot find identity zone for subdomain "
                    + subdomain);
            return;
        }
        try {
            IdentityZoneHolder.set(identityZone);
            filterChain.doFilter(request, response);
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    private String getSubdomain(String hostname) {
        if (hostname.equals(uaaHostname)) {
            return "";
        }
        if (hostname.endsWith("." + uaaHostname)) {
            return hostname.substring(0, hostname.length() - uaaHostname.length() - 1);
        }
        return null;
    }

    @Autowired
    public void setDao(IdentityZoneProvisioning dao) {
        this.dao = dao;
    }

    @Value("${uaaHostname:localhost}")
    public void setUaaHostname(String uaaHostname) {
        this.uaaHostname = uaaHostname;
    }

}
