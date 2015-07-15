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
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;

public class UaaUrlUtils {

    private final String uaaBaseUrl;

    public UaaUrlUtils(String uaaBaseUrl) {
        this.uaaBaseUrl = uaaBaseUrl;
    }

    public String getUaaUrl() {
        return getUaaUrl("");
    }

    public String getUaaUrl(String path) {
        return getURIBuilder(path).build().toUriString();
    }

    public String getUaaHost() {
        return getURIBuilder("").build().getHost();
    }

    private UriComponentsBuilder getURIBuilder(String path) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(uaaBaseUrl).path(path);
        String subdomain = IdentityZoneHolder.get().getSubdomain();
        if (!StringUtils.isEmpty(subdomain)) {
            builder.host(subdomain + "." + builder.build().getHost());
        }
        return builder;
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

    public static String extractPathVariableFromUrl(int pathParameterIndex, String pathInfo) {
        if (pathInfo.startsWith("/")) {
            pathInfo = pathInfo.substring(1);
        }
        String[] paths = StringUtils.delimitedListToStringArray(pathInfo, "/");
        if (paths.length!=0 && pathParameterIndex<paths.length) {
            return paths[pathParameterIndex];
        }
        return null;
    }

    public static String getRequestPath(HttpServletRequest request) {
        String pathInfo = StringUtils.hasLength(request.getRequestURI()) ? request.getRequestURI() : request.getPathInfo();
        return pathInfo;
    }


}
