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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;

import java.net.URISyntaxException;

public class UaaUrlUtils {

    private final Log logger = LogFactory.getLog(getClass());

    private final String uaaBaseUrl;

    public UaaUrlUtils(@Value("${uaaBaseUrl}") String uaaBaseUrl) {
        this.uaaBaseUrl = uaaBaseUrl;
    }

    public String getUaaUrl() {
        return getUaaUrl("");
    }

    public String getUaaUrl(String path) {
        return getURIBuilder(path).toString();
    }

    public String getUaaHost() {
        return getURIBuilder("").getHost();
    }

    private URIBuilder getURIBuilder(String path) {
        URIBuilder builder = null;
        try {
            builder = new URIBuilder(uaaBaseUrl + path);
            String subdomain = IdentityZoneHolder.get().getSubdomain();
            if (!StringUtils.isEmpty(subdomain)) {
                builder.setHost(subdomain + "." + builder.getHost());
            }
            return builder;
        } catch (URISyntaxException e) {
            logger.error("Exception raised when building URI " + e);
        }
        return builder;
    }
}
