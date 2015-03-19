/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This filter ensures that all requests are targeting a specific identity zone
 * by hostname. If the hostname doesn't match an identity zone, a 404 error is
 * sent.
 * 
 * @author wtran@pivotal.io
 * @author rszumlakowski@pivotal.io
 *
 */
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
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Cannot find identity zone for subdomain " + subdomain);
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

    public void setIdentityZoneProvisioning(IdentityZoneProvisioning dao) {
        this.dao = dao;
    }

    public void setInternalHostnames(Set<String> hostnames) {
        internalHostnames = Collections.unmodifiableSet(hostnames);
    }

    public Set<String> getInternalHostnames() {
        return internalHostnames;
    }
}
