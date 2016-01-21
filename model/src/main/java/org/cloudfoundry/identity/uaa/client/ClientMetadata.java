package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.net.URL;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientMetadata {

    private String clientId;
    private String identityZoneId;
    private boolean showOnHomePage;
    private URL appLaunchUrl;
    private String appIcon;
    private int version;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @JsonIgnore
    public String getIdentityZoneId() {
        return identityZoneId;
    }

    @JsonIgnore
    public void setIdentityZoneId(String identityZoneId) {
        this.identityZoneId = identityZoneId;
    }

    public boolean isShowOnHomePage() {
        return showOnHomePage;
    }

    public void setShowOnHomePage(boolean showOnHomePage) {
        this.showOnHomePage = showOnHomePage;
    }

    public URL getAppLaunchUrl() {
        return appLaunchUrl;
    }

    public void setAppLaunchUrl(URL appLaunchUrl) {
        this.appLaunchUrl = appLaunchUrl;
    }

    public String getAppIcon() {
        return appIcon;
    }

    public void setAppIcon(String appIcon) {
        this.appIcon = appIcon;
    }
}
