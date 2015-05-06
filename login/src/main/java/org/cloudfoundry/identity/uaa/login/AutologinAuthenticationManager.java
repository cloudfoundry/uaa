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
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.Map;

/**
 * @author Dave Syer
 * 
 */
public class AutologinAuthenticationManager implements AuthenticationManager {

    private Log logger = LogFactory.getLog(getClass());

    private ExpiringCodeStore codeStore;

    public ExpiringCodeStore getExpiringCodeStore() {
        return codeStore;
    }

    public void setExpiringCodeStore(ExpiringCodeStore expiringCodeStore) {
        this.codeStore= expiringCodeStore;
    }

    public ExpiringCode doRetrieveCode(String code) {
        return codeStore.retrieveCode(code);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!(authentication instanceof AuthzAuthenticationRequest)) {
            return null;
        }

        AuthzAuthenticationRequest request = (AuthzAuthenticationRequest) authentication;
        Map<String, String> info = request.getInfo();
        String code = info.get("code");

        ExpiringCode ec = doRetrieveCode(code);
        SocialClientUserDetails user = null;
        try {
            if (ec != null) {
                user = JsonUtils.readValue(ec.getData(), SocialClientUserDetails.class);
            }
        } catch (JsonUtils.JsonUtilException x) {
            throw new BadCredentialsException("JsonConversion error", x);
        }

        if (user == null) {
            throw new BadCredentialsException("Cannot redeem provided code for user");
        }

        // ensure that we stored clientId
        String clientId = null;
        String origin = null;
        String userId = null;
        Object principal = user.getUsername();
        if (user.getDetails() instanceof String) {
            clientId = (String) user.getDetails();
        } else if (user.getDetails() instanceof Map) {
            Map<String,String> map = (Map<String,String>)user.getDetails();
            clientId = map.get("client_id");
            origin = map.get(Origin.ORIGIN);
            userId = map.get("user_id");
            principal = new UaaPrincipal(userId,user.getUsername(),null,origin,null, IdentityZoneHolder.get().getId());
        }
        if (clientId == null) {
            throw new BadCredentialsException("Cannot redeem provided code for user, client id missing");
        }

        // validate the client Id
        if (!(authentication.getDetails() instanceof UaaAuthenticationDetails)) {
            throw new BadCredentialsException("Cannot redeem provided code for user, auth details missing");
        }

        UaaAuthenticationDetails details = (UaaAuthenticationDetails) authentication.getDetails();
        if (!clientId.equals(details.getClientId())) {
            throw new BadCredentialsException("Cannot redeem provided code for user, client mismatch");
        }

        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal, null, user.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;

    }

}
