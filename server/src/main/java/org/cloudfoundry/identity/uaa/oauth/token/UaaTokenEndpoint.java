/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.POST;


@Controller
public class UaaTokenEndpoint {

    @Autowired
    TokenEndpoint delegate;

    @RequestMapping(value = "/oauth/token/**", method = POST)
    public ResponseEntity<OAuth2AccessToken> doDelegate(Principal principal,
                                                        @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        return delegate.postAccessToken(principal, parameters);
    }
}
