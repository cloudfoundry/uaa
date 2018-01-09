/*******************************************************************************
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

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;

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

    private boolean addNew;

    private final String origin;

    private String sessionId;

    private String clientId;

    private UaaAuthenticationDetails() {
        this.origin = "unknown";
        this.sessionId = "unknown";
        this.clientId = "unknown";
    }

    public UaaAuthenticationDetails(HttpServletRequest request) {
        this(request, null);
    }
    public UaaAuthenticationDetails(HttpServletRequest request, String clientId) {
        WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request);
        this.origin = webAuthenticationDetails.getRemoteAddress();
        this.sessionId = webAuthenticationDetails.getSessionId();

        if (clientId == null) {
            this.clientId = request.getParameter("client_id");
            if(!StringUtils.hasText(this.clientId)) {
                String authHeader = request.getHeader("Authorization");
                if(StringUtils.hasText(authHeader) && authHeader.startsWith("Basic ")) {
                    String decodedCredentials = new String(Base64.decode(authHeader.substring("Basic ".length())));
                    String[] split = decodedCredentials.split(":");
                    this.clientId = split[0];
                }
            }
        } else {
            this.clientId = clientId;
        }
        this.addNew = Boolean.parseBoolean(request.getParameter(ADD_NEW));
    }

    public UaaAuthenticationDetails(@JsonProperty("addNew") boolean addNew,
                                    @JsonProperty("clientId") String clientId,
                                    @JsonProperty("origin") String origin,
                                    @JsonProperty("sessionId") String sessionId) {
        this.addNew = addNew;
        this.clientId = clientId;
        this.origin = origin;
        this.sessionId = sessionId;
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
        return sb.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
        result = prime * result + ((origin == null) ? 0 : origin.hashCode());
        result = prime * result + ((sessionId == null) ? 0 : sessionId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        UaaAuthenticationDetails other = (UaaAuthenticationDetails) obj;
        if (clientId == null) {
            if (other.clientId != null)
                return false;
        }
        else if (!clientId.equals(other.clientId))
            return false;
        if (origin == null) {
            if (other.origin != null)
                return false;
        }
        else if (!origin.equals(other.origin))
            return false;
        if (sessionId == null) {
            if (other.sessionId != null)
                return false;
        }
        else if (!sessionId.equals(other.sessionId))
            return false;
        return true;
    }

}
