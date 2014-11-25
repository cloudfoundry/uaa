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

package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.ui.Model;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

/**
 * Contains basic information used by the
 * login-server controllers.
 * 
 * @author fhanik
 * 
 */
public abstract class AbstractControllerInfo {
    private final Log logger = LogFactory.getLog(getClass());
    private Map<String, String> links = new HashMap<String, String>();
    private static String DEFAULT_BASE_UAA_URL = "https://uaa.cloudfoundry.com";
    protected static final String HOST = "Host";
    protected static final String AUTHORIZATON = "Authorization";

    private Properties gitProperties = new Properties();

    private Properties buildProperties = new Properties();

    private String baseUrl;

    private String uaaHost;

    /**
     * @param links the links to set
     */
    public void setLinks(Map<String, String> links) {
        this.links = links;
    }

    public Map<String, String> getLinks() {
        return links;
    }

    protected void initProperties() {
        setUaaBaseUrl(DEFAULT_BASE_UAA_URL);
        try {
            gitProperties = PropertiesLoaderUtils.loadAllProperties("git.properties");
        } catch (IOException e) {
            // Ignore
        }
        try {
            buildProperties = PropertiesLoaderUtils.loadAllProperties("build.properties");
        } catch (IOException e) {
            // Ignore
        }

    }

    /**
     * @param baseUrl the base uaa url
     */
    public void setUaaBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
        try {
            URI uri = new URI(baseUrl);
            this.uaaHost = uri.getHost();
            if (uri.getPort()!=443 && uri.getPort()!=80 && uri.getPort()>0) {
                //append non standard ports to the hostname
                this.uaaHost += ":"+uri.getPort();
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Could not extract host from URI: " + baseUrl);
        }
    }

    protected String getUaaBaseUrl() {
        return baseUrl;
    }

    protected String getUaaHost() {
        return uaaHost;
    }

    protected Map<String, ?> getLinksInfo() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("uaa", getUaaBaseUrl());
        model.put("login", getUaaBaseUrl().replaceAll("uaa", "login"));
        model.putAll(getLinks());
        return model;
    }

    protected HttpHeaders getRequestHeaders(HttpHeaders headers) {
        // Some of the headers coming back are poisonous apparently
        // (content-length?)...
        HttpHeaders outgoingHeaders = new HttpHeaders();
        outgoingHeaders.putAll(headers);
        outgoingHeaders.remove(HOST);
        outgoingHeaders.remove(HOST.toLowerCase());
        outgoingHeaders.set(HOST, getUaaHost());
        logger.debug("Outgoing headers: " + outgoingHeaders);
        return outgoingHeaders;
    }

    protected String extractPath(HttpServletRequest request) {
        String query = request.getQueryString();
        try {
            query = query == null ? "" : "?" + URLDecoder.decode(query, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Cannot decode query string: " + query);
        }
        String path = request.getRequestURI() + query;
        String context = request.getContextPath();
        path = path.substring(context.length());
        if (path.startsWith("/")) {
            // In the root context we have to remove this as well
            path = path.substring(1);
        }
        logger.debug("Path: " + path);
        return path;
    }

    protected void populateBuildAndLinkInfo(Model model) {
        Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("links", getLinksInfo());
        model.addAllAttributes(attributes);
        model.addAttribute("links", getLinks());
    }

    protected void setCommitInfo(Map<String, Object> model) {
        model.put("commit_id", gitProperties.getProperty("git.commit.id.abbrev", "UNKNOWN"));
        model.put(
            "timestamp",
            gitProperties.getProperty("git.commit.time",
                new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())));
        model.put("app", UaaStringUtils.getMapFromProperties(buildProperties, "build."));

    }
}
