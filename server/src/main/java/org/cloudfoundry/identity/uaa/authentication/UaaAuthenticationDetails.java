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
package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import jakarta.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.util.StringUtils.hasText;

/**
 * Contains additional information about the authentication request which may be
 * of use in auditing etc.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UaaAuthenticationDetails implements Serializable {

    public static final String ADD_NEW = "add_new";

    public static final UaaAuthenticationDetails UNKNOWN = new UaaAuthenticationDetails();

    private static final String[] filteredParamKeys = {"username", "password", "passcode"};
    private static final String UNKNOWN_STRING = "unknown";

    private UaaLoginHint loginHint;

    private boolean addNew;

    private final String origin;

    private String sessionId;

    private String clientId;

    @JsonIgnore
    private String authenticationMethod;

    @JsonIgnore
    private final String requestPath;

    @JsonIgnore
    private final boolean isAuthorizationSet;

    @JsonIgnore
    private Map<String, String[]> parameterMap;

    protected UaaAuthenticationDetails() {
        this.origin = UNKNOWN_STRING;
        this.sessionId = UNKNOWN_STRING;
        this.clientId = UNKNOWN_STRING;
        this.requestPath = UNKNOWN_STRING;
        this.isAuthorizationSet = false;
    }

    public UaaAuthenticationDetails(HttpServletRequest request) {
        this(request, null);
    }

    public UaaAuthenticationDetails(HttpServletRequest request, String clientId) {
        WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request);
        this.origin = webAuthenticationDetails.getRemoteAddress();
        this.sessionId = webAuthenticationDetails.getSessionId();
        this.requestPath = StringUtils.removeEnd(request.getRequestURI().substring(request.getContextPath().length()), "/");
        this.isAuthorizationSet = request.getHeader(HttpHeaders.AUTHORIZATION) != null;

        if (clientId == null) {
            this.clientId = request.getParameter("client_id");
            if (!hasText(this.clientId)) {
                this.clientId = (String) request.getAttribute("clientId");
            }
        } else {
            this.clientId = clientId;
        }
        this.addNew = Boolean.parseBoolean(request.getParameter(ADD_NEW));
        this.loginHint = UaaLoginHint.parseRequestParameter(request.getParameter("login_hint"));
        this.parameterMap = request.getParameterMap().entrySet().stream()
                .filter(param -> ArrayUtils.indexOf(filteredParamKeys, param.getKey().toLowerCase()) == -1)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public UaaAuthenticationDetails(@JsonProperty("addNew") boolean addNew,
            @JsonProperty("clientId") String clientId,
            @JsonProperty("origin") String origin,
            @JsonProperty("sessionId") String sessionId) {
        this.addNew = addNew;
        this.clientId = clientId;
        this.origin = origin;
        this.sessionId = sessionId;
        this.requestPath = UNKNOWN_STRING;
        this.isAuthorizationSet = false;
    }

    public String getOrigin() {
        return origin;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientId() {
        return clientId;
    }

    public boolean isAddNew() {
        return addNew;
    }

    public void setAddNew(boolean addNew) {
        this.addNew = addNew;
    }

    public UaaLoginHint getLoginHint() {
        return loginHint;
    }

    public void setLoginHint(UaaLoginHint loginHint) {
        this.loginHint = loginHint;
    }

    public Map<String, String[]> getParameterMap() {
        return parameterMap != null ? new HashMap<>(parameterMap) : null;
    }

    @JsonIgnore
    public String getAuthenticationMethod() {
        return this.authenticationMethod;
    }

    @JsonIgnore
    protected void setAuthenticationMethod(final String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }

    @JsonIgnore
    public String getRequestPath() {
        return this.requestPath;
    }

    @JsonIgnore
    public boolean isAuthorizationSet() {
        return this.isAuthorizationSet;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (origin != null) {
            sb.append("remoteAddress=").append(origin);
        }
        if (clientId != null) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("clientId=").append(clientId);
        }
        if (sessionId != null) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("sessionId=<SESSION>");
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (clientId == null ? 0 : clientId.hashCode());
        result = prime * result + (origin == null ? 0 : origin.hashCode());
        result = prime * result + (sessionId == null ? 0 : sessionId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        UaaAuthenticationDetails other = (UaaAuthenticationDetails) obj;
        if (clientId == null) {
            if (other.clientId != null) {
                return false;
            }
        } else if (!clientId.equals(other.clientId)) {
            return false;
        }
        if (origin == null) {
            if (other.origin != null) {
                return false;
            }
        } else if (!origin.equals(other.origin)) {
            return false;
        }
        if (sessionId == null) {
            if (other.sessionId != null) {
                return false;
            }
        } else if (!sessionId.equals(other.sessionId)) {
            return false;
        }
        return true;
    }

}
