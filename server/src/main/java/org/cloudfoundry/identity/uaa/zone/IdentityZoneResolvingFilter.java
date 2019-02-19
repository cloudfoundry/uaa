/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This filter ensures that all requests are targeting a specific identity zone
 * by hostname. If the hostname doesn't match an identity zone, a 404 error is
 * sent.
 *
 */
public class IdentityZoneResolvingFilter extends OncePerRequestFilter implements InitializingBean {

    private IdentityZoneProvisioning dao;
    private Set<String> defaultZoneHostnames = new HashSet<>();
    private Log logger = LogFactory.getLog(getClass());

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
                logger.debug("Cannot find identity zone for subdomain " + subdomain);
            } catch (Exception ex) {
                String message = "Internal server error while fetching identity zone for subdomain" + subdomain;
                logger.warn(message, ex);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
                return;
            }
        }
        if (identityZone == null) {
            request.setAttribute("error_message_code", "zone.not.found");
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
        String lowerHostName = hostname.toLowerCase();
        if (defaultZoneHostnames.contains(lowerHostName)) {
            return "";
        }
        for (String internalHostname : defaultZoneHostnames) {
            if (lowerHostName.endsWith("." + internalHostname)) {
                return lowerHostName.substring(0, lowerHostName.length() - internalHostname.length() - 1);
            }
        }
        //UAA is catch all if we haven't configured anything
        if (defaultZoneHostnames.size()==1 && defaultZoneHostnames.contains("localhost")) {
            logger.debug("No root domains configured, UAA is catch-all domain for host:"+hostname);
            return "";
        }
        logger.debug("Unable to determine subdomain for host:"+hostname+"; root domains:"+Arrays.toString(defaultZoneHostnames.toArray()));
        return null;
    }

    public void setIdentityZoneProvisioning(IdentityZoneProvisioning dao) {
        this.dao = dao;
    }

    public void setAdditionalInternalHostnames(Set<String> hostnames) {
        if (hostnames!=null) {
            hostnames
                .stream()
                .forEach(
                  entry -> this.defaultZoneHostnames.add(entry.toLowerCase())
                 );
        }
    }

    public void setDefaultInternalHostnames(Set<String> hostnames) {
        if (hostnames!=null) {
            hostnames
                .stream()
                .forEach(
                        entry -> this.defaultZoneHostnames.add(entry.toLowerCase())
                );
        }
    }

    public synchronized void restoreDefaultHostnames(Set<String> hostnames) {
        this.defaultZoneHostnames.clear();
        if (hostnames!=null) {
            hostnames
                .stream()
                .forEach(
                        entry -> this.defaultZoneHostnames.add(entry.toLowerCase())
                );
        }
    }

    public Set<String> getDefaultZoneHostnames() {
        return new HashSet<>(defaultZoneHostnames);
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        logger.info("Zone Resolving Root domains are: "+ Arrays.toString(getDefaultZoneHostnames().toArray()));
    }
}
