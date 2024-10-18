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
package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.net.URL;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientMetadata {

    private String clientId;
    private String clientName;
    private String identityZoneId;
    private boolean showOnHomePage;
    private URL appLaunchUrl;
    private String appIcon;
    private String createdBy;

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

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public ClientMetadata setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
        return this;
    }
}
