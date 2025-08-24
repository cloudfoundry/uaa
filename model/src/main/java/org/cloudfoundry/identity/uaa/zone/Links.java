/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Optional;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Links {

    private SelfService service = new SelfService();
    private Logout logout = new Logout();
    private String homeRedirect;

    public Logout getLogout() {
        return logout;
    }

    public Links setLogout(Logout logout) {
        this.logout = logout;
        return this;
    }

    public SelfService getSelfService() {
        return service;
    }

    public Links setSelfService(SelfService service) {
        this.service = service;
        return this;
    }

    public String getHomeRedirect() {
        return homeRedirect;
    }

    public Links setHomeRedirect(String homeRedirect) {
        this.homeRedirect = homeRedirect;
        return this;
    }

    public static class Logout {
        private String redirectUrl = "/login";
        private String redirectParameterName = "redirect";
        private boolean disableRedirectParameter;
        private List<String> whitelist;

        public boolean isDisableRedirectParameter() {
            return false;
        }

        public Logout setDisableRedirectParameter(boolean disableRedirectParameter) {
            return this;
        }

        public String getRedirectParameterName() {
            return redirectParameterName;
        }

        public Logout setRedirectParameterName(String redirectParameterName) {
            this.redirectParameterName = redirectParameterName;
            return this;
        }

        public String getRedirectUrl() {
            return Optional.ofNullable(redirectUrl).orElse("/login");
        }

        public Logout setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }

        public List<String> getWhitelist() {
            return whitelist;
        }

        public Logout setWhitelist(List<String> whitelist) {
            this.whitelist = whitelist;
            return this;
        }
    }

    public static class SelfService {
        private boolean selfServiceLinksEnabled = true;
        private String signup;
        private String passwd;

        public boolean isSelfServiceLinksEnabled() {
            return selfServiceLinksEnabled;
        }

        public SelfService setSelfServiceLinksEnabled(boolean selfServiceLinksEnabled) {
            this.selfServiceLinksEnabled = selfServiceLinksEnabled;
            return this;
        }

        public String getPasswd() {
            return passwd;
        }

        public SelfService setPasswd(String passwd) {
            this.passwd = passwd;
            return this;
        }

        public String getSignup() {
            return signup;
        }

        public SelfService setSignup(String signup) {
            this.signup = signup;
            return this;
        }
    }

}
