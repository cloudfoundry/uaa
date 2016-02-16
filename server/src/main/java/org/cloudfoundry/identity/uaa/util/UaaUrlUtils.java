/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Set;
import java.util.regex.Pattern;

public class UaaUrlUtils {

    public UaaUrlUtils() {}

    public String getUaaUrl() {
        return getUaaUrl("");
    }

    public static String getUaaUrl(String path) {
        return getURIBuilder(path).build().toUriString();
    }

    public String getUaaHost() {
        return getURIBuilder("").build().getHost();
    }

    private static UriComponentsBuilder getURIBuilder(String path) {
        UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentContextPath().path(path);
        return builder;
    }

    public static String findMatchingRedirectUri(Collection<String> wildcardUris, String requestedRedirectUri, String fallbackRedirectUri) {
        if (wildcardUris == null || UaaStringUtils.matches(UaaStringUtils.constructWildcards(wildcardUris), requestedRedirectUri) ) {
            return requestedRedirectUri;
        }
        return fallbackRedirectUri;
    }

    public static String getHostForURI(String uri) {
        UriComponentsBuilder b = UriComponentsBuilder.fromHttpUrl(uri);
        return b.build().getHost();
    }

    public static boolean isUrl(String url) {
        try {
            new URL(url);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    public static String addSubdomainToUrl(String url) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        builder.host(getSubdomain() + builder.build().getHost());
        return builder.build().toUriString();
    }

    public static String getSubdomain() {
        String subdomain = IdentityZoneHolder.get().getSubdomain();
        if (StringUtils.hasText(subdomain)) {
            subdomain += ".";
        }
        return subdomain.trim();
    }

    public static String extractPathVariableFromUrl(int pathParameterIndex, String path) {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        String[] paths = StringUtils.delimitedListToStringArray(path, "/");
        if (paths.length!=0 && pathParameterIndex<paths.length) {
            return paths[pathParameterIndex];
        }
        return null;
    }

    public static String getRequestPath(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();

        if(servletPath == null) { servletPath = ""; }
        if(pathInfo == null) { pathInfo = ""; }

        String path = String.format("%s%s", servletPath, pathInfo);
        return path;
    }
}
