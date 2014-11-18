package org.cloudfoundry.identity.uaa.zone;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

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

    private Set<String> internalHostnames = new HashSet<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        IdentityZone identityZone = null;
        String hostname = request.getServerName();
        String subdomain = getSubdomain(hostname);
        if (subdomain != null) {
            try {
                identityZone = dao.retrieveBySubdomain(subdomain);
            } catch (EmptyResultDataAccessException ex) {
            } catch (Exception ex) {
                throw ex;
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
        if (internalHostnames.contains(hostname)) {
            return "";
        }
        for (String internalHostname : internalHostnames) {
            if (hostname.endsWith("." + internalHostname)) {
                return hostname.substring(0, hostname.length() - internalHostname.length() - 1);
            }
        }
        return null;
    }

    @Autowired
    public void setDao(IdentityZoneProvisioning dao) {
        this.dao = dao;
    }

    @Value("${internalHostnames:localhost}")
    public void setInternalHostnames(String hostnames) {
        this.internalHostnames.clear();
        this.internalHostnames.addAll(Arrays.asList(hostnames.split("[ ,]+")));
    }

}
