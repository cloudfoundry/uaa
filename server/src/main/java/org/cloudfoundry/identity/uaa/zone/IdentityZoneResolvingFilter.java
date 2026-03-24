/*
 * *****************************************************************************
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

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    private final IdentityZoneProvisioning dao;
    private final Set<String> staticResources = Set.of("/resources/", "/vendor/font-awesome/");
    private final Set<String> defaultZoneHostnames = new HashSet<>();
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public IdentityZoneResolvingFilter(final IdentityZoneProvisioning dao) {
        this.dao = dao;
    }

    private static final String INTERNAL_ERROR_MESSAGE = "Internal server error while fetching identity zone for subdomain ";
    private static final String NOT_FOUND_MESSAGE = "Cannot find identity zone for subdomain ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String effectiveSubdomain = resolveEffectiveSubdomain(request, response);
        if (effectiveSubdomain == null && response.isCommitted()) {
            return;
        }

        IdentityZone identityZone = resolveZoneBySubdomain(effectiveSubdomain, response);
        if (response.isCommitted()) {
            return;
        }
        if (identityZone == null) {
            handleZoneNotFound(effectiveSubdomain, request, response, filterChain);
            return;
        }
        doFilterWithZone(identityZone, request, response, filterChain);
    }

    /**
     * Resolves the effective subdomain from path (zone path attribute) or hostname. Sends 400 if both are present.
     *
     * @return the subdomain to use, or null if from hostname and host did not match any zone root (caller must check response.isCommitted() for 400)
     */
    private String resolveEffectiveSubdomain(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String subdomainFromPath = (String) request.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH);
        String subdomainFromHost = getSubdomainFromHost(request.getServerName());
        if (subdomainFromPath != null) {
            if (subdomainFromHost != null && !subdomainFromHost.isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Cannot use both subdomain and zone path");
                return null;
            }
            return subdomainFromPath;
        }
        return subdomainFromHost;
    }

    /**
     * Looks up identity zone by subdomain. On generic exception sends 500 and returns null; caller should check response.isCommitted().
     */
    private IdentityZone resolveZoneBySubdomain(String subdomain, HttpServletResponse response) throws IOException {
        if (subdomain == null) {
            return null;
        }
        try {
            return dao.retrieveBySubdomain(subdomain);
        } catch (EmptyResultDataAccessException ex) {
            logger.debug("Cannot find identity zone for subdomain {}", subdomain);
            return null;
        } catch (Exception ex) {
            String message = INTERNAL_ERROR_MESSAGE + subdomain;
            logger.warn(message, ex);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
            return null;
        }
    }

    /**
     * Handles the case when no zone was found: serve static resources or send 404. Caller must return after calling.
     */
    private void handleZoneNotFound(String subdomain, HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        boolean isStaticResource = staticResources.stream().anyMatch(UaaUrlUtils.getRequestPath(request)::startsWith);
        if (isStaticResource) {
            filterChain.doFilter(request, response);
            return;
        }
        request.setAttribute("error_message_code", "zone.not.found");
        response.sendError(HttpServletResponse.SC_NOT_FOUND, NOT_FOUND_MESSAGE + subdomain);
    }

    private void doFilterWithZone(IdentityZone identityZone, HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            IdentityZoneHolder.set(identityZone);
            filterChain.doFilter(request, response);
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    private String getSubdomainFromHost(String hostname) {
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
        if (defaultZoneHostnames.size() == 1 && defaultZoneHostnames.contains("localhost")) {
            logger.debug("No root domains configured, UAA is catch-all domain for host:{}", hostname);
            return "";
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Unable to determine subdomain for host:{}; root domains:{}", hostname, Arrays.toString(defaultZoneHostnames.toArray()));
        }
        return null;
    }

    public void setAdditionalInternalHostnames(Set<String> hostnames) {
        if (hostnames != null) {
            hostnames
                    .forEach(
                            entry -> this.defaultZoneHostnames.add(entry.toLowerCase())
                    );
        }
    }

    public void setDefaultInternalHostnames(Set<String> hostnames) {
        if (hostnames != null) {
            hostnames
                    .forEach(
                            entry -> this.defaultZoneHostnames.add(entry.toLowerCase())
                    );
        }
    }

    public synchronized void restoreDefaultHostnames(Set<String> hostnames) {
        this.defaultZoneHostnames.clear();
        if (hostnames != null) {
            hostnames
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
        String domainArray = Arrays.toString(getDefaultZoneHostnames().toArray());
        logger.info("Zone Resolving Root domains are: {}", domainArray);
    }
}
