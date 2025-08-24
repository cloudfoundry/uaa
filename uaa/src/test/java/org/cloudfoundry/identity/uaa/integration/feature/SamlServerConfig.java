/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2025] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.integration.feature;

import org.openqa.selenium.WebDriver;

/**
 * @author fhanik
 */
public class SamlServerConfig {
    private static final String SAML_AUTH_SOURCE = "example-userpass";
    private static final String SIMPLESAMLPHP_UAA_ACCEPTANCE = "http://simplesamlphp.uaa-acceptance.cf-app.com";
    private static final String SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR = "//%s[contains(text(), 'Enter your username and password')]";

    private String serverUrl;

    SamlServerConfig(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getSamlServerUrl() {
        return this.serverUrl;
    }

    public boolean isUpgraded() {
        return !SIMPLESAMLPHP_UAA_ACCEPTANCE.equals(getSamlServerUrl());
    }

    public String getLoginPromptXpathExpr() {
        return isUpgraded() ?
                SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR.formatted("h2") :
                SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR.formatted("h1");
    }

    public void logOut(WebDriver webDriver) {
        if (isUpgraded()) {
            webDriver.get(this.getSamlServerUrl() + "/logout.php");
            webDriver.get(this.getSamlServerUrl() + "/index.php");
        } else {
            String URL_PATH = "/module.php/core/logout";
            webDriver.get(this.getSamlServerUrl() + URL_PATH + "/" + SAML_AUTH_SOURCE);
        }
    }

    public String getWelcomePath() {
        return isUpgraded() ? "module.php/core/frontpage_welcome.php" : "module.php/core/welcome";
    }

}
