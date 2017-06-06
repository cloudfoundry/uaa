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

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public abstract class UaaUrlUtils {

    public static String getUaaUrl() {
        return getUaaUrl("");
    }

    public static String getUaaUrl(String path) {
        return getUaaUrl(path, false);
    }
    public static String getUaaUrl(String path, boolean zoneSwitchPossible) {
        return getURIBuilder(path, zoneSwitchPossible).build().toUriString();
    }

    public static String getUaaHost() {
        return getURIBuilder("").build().getHost();
    }

    public static UriComponentsBuilder getURIBuilder(String path) {
        return getURIBuilder(path, false);
    }
    public static UriComponentsBuilder getURIBuilder(String path, boolean zoneSwitchPossible) {
        UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentContextPath().path(path);
        if (zoneSwitchPossible) {
            String host = builder.build().getHost();
            IdentityZone current = IdentityZoneHolder.get();
            if (host != null && !IdentityZoneHolder.isUaa()) {
                if (!host.startsWith(current.getSubdomain() + ".")) {
                    host = current.getSubdomain() + "." + host;
                    builder.host(host);
                }
            }
        }
        return builder;
    }

    public static boolean isValidRegisteredRedirectUrl(String url) {
        if (hasText(url)) {
            final String permittedURLs =
                    "^(http(\\*|s)?://)" +    //URL starts with 'www.' or 'http://' or 'https://' or 'http*://
                    "((.*:.*@)?)"+                   //username/password in URL
                    "([a-zA-Z0-9\\-\\*\\.]+)" +      //hostname
                    "(:.*|/.*|$)?";                  //port and path
            Matcher matchResult = Pattern.compile(permittedURLs).matcher(url);
            if (matchResult.matches()) {
                String host = matchResult.group(5);
                String[] segments = host.split("\\.");
                //last two segments are not allowed to contain wildcards
                for (int i=0; i<2 && i<segments.length; i++) {
                    int index = segments.length - i - 1;
                    if (segments[index].indexOf('*')>=0) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Finds and returns a matching redirect URL according to the following logic:
     * <ul>
     *     <li>If the requstedRedirectUri matches the whitelist the requestedRedirectUri is returned</li>
     *     <li>If the whitelist is null or empty AND the fallbackRedirectUri is null, the requestedRedirectUri is returned - OPEN REDIRECT</li>
     *     <li>If the whitelist is null or empty AND the fallbackRedirectUri is not null, the fallbackRedirectUri is returned</li>
     * </ul>
     * @param redirectUris - a whitelist collection of ant path patterns
     * @param requestedRedirectUri - the requested redirect URI, returned if whitelist matches or the fallbackRedirectUri is null
     * @param fallbackRedirectUri - returned if non null and the requestedRedirectUri doesn't match the whitelist redirectUris
     * @return a redirect URI, either the requested or fallback as described above
     */
    public static String findMatchingRedirectUri(Collection<String> redirectUris, String requestedRedirectUri, String fallbackRedirectUri) {
        AntPathMatcher matcher = new AntPathMatcher();

        for (String pattern : ofNullable(redirectUris).orElse(emptyList())) {
            if (matcher.match(pattern, requestedRedirectUri)) {
                return requestedRedirectUri;
            }
        }

        return ofNullable(fallbackRedirectUri).orElse(requestedRedirectUri);
    }

    public static String getHostForURI(String uri) {
        UriComponentsBuilder b = UriComponentsBuilder.fromHttpUrl(uri);
        return b.build().getHost();
    }

    public static String getBaseURL(HttpServletRequest request) {
        //returns scheme, host and context path
        //for example http://localhost:8080/uaa or http://login.uaa-acceptance.cf-app.com
        String requestURL = request.getRequestURL().toString();
        return hasText(request.getServletPath()) ?
            requestURL.substring(0, requestURL.lastIndexOf(request.getServletPath())) :
            requestURL;
    }

    public static Map<String, String[]> getParameterMap(String uri) {
        UriComponentsBuilder b = UriComponentsBuilder.fromUriString(uri);
        MultiValueMap<String, String> map = b.build().getQueryParams();
        Map<String, String[]> result= new HashMap<>();
        map
            .entrySet()
            .stream()
            .forEach(
                e -> result.put(e.getKey(), decodeValue(e.getValue()))
            );
        return result;
    }

    public static String[] decodeValue(List<String> value) {
        if (value==null) {
            return null;
        }
        String[] result = new String[value.size()];
        int pos = 0;
        for (String s : value) {
            try {
                result[pos++] = UriUtils.decode(s, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalArgumentException(s, e);
            }
        }
        return result;
    }

    public static boolean isUrl(String url) {
        try {
            new URL(url);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    public static String addQueryParameter(String url, String name, String value) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        builder.queryParam(name,value);
        return builder.build().toUriString();
    }

    public static String addFragmentComponent(String urlString, String component) {
        URI uri = URI.create(urlString);
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(uri);
        builder.fragment(hasText(uri.getFragment()) ? uri.getFragment() + "&" + component : component);
        return builder.build().toUriString();
    }

    public static String addSubdomainToUrl(String url) {
        return addSubdomainToUrl(url, getSubdomain());
    }
    public static String addSubdomainToUrl(String url, String subdomain) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        builder.host(subdomain + builder.build().getHost());
        return builder.build().toUriString();
    }

    public static String getSubdomain() {
        String subdomain = IdentityZoneHolder.get().getSubdomain();
        if (hasText(subdomain)) {
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
