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


}
