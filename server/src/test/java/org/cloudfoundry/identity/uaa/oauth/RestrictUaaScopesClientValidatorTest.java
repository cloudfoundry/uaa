/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.RestrictUaaScopesClientValidator;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.UaaScopes;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode.MODIFY;


class RestrictUaaScopesClientValidatorTest {

    List<String> goodScopes = Arrays.asList("openid", "uaa.resource", "uaa.none");
    List<String> badScopes = new UaaScopes().getUaaScopes();
    RestrictUaaScopesClientValidator validator = new RestrictUaaScopesClientValidator(new UaaScopes());

    @Test
    void validate() {
        List<ClientDetailsValidator.Mode> restrictModes = Arrays.asList(CREATE, MODIFY);
        List<ClientDetailsValidator.Mode> nonRestrictModes = Collections.singletonList(DELETE);
        UaaClientDetails client = new UaaClientDetails("clientId", "", "", "client_credentials,password", "");

        for (String s : badScopes) {
            client.setScope(Collections.singletonList(s));
            validateClient(restrictModes, nonRestrictModes, client, s);
            client.setScope(Collections.emptyList());
            client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(s)));
            validateClient(restrictModes, nonRestrictModes, client, s);
            client.setAuthorities(Collections.emptyList());
        }

        for (String s : goodScopes) {
            List<ClientDetailsValidator.Mode> goodmodes = new LinkedList<>(restrictModes);
            goodmodes.addAll(nonRestrictModes);
            client.setScope(Collections.singletonList(s));
            validateClient(Collections.emptyList(), goodmodes, client, s);
            client.setScope(Collections.emptyList());
            client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(s)));
            validateClient(Collections.emptyList(), goodmodes, client, s);
            client.setAuthorities(Collections.emptyList());
        }

    }

    protected void validateClient(List<ClientDetailsValidator.Mode> restrictModes, List<ClientDetailsValidator.Mode> nonRestrictModes, UaaClientDetails client, String s) {
        for (ClientDetailsValidator.Mode m : restrictModes) {
            try {
                validator.validate(client, m);
                fail("Scope:" + s + " should not be valid during " + m + " mode.");
            } catch (InvalidClientDetailsException x) {
                //expected
            }
        }
        for (ClientDetailsValidator.Mode m : nonRestrictModes) {
            try {
                validator.validate(client, m);
            } catch (InvalidClientDetailsException x) {
                fail("Scope:" + s + " should be valid during " + m + " mode.");
            }
        }
  }
}
