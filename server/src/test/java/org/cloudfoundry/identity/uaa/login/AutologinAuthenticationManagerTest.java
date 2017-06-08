package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.manager.AutologinAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
public class AutologinAuthenticationManagerTest {

    private AutologinAuthenticationManager manager;
    private ExpiringCodeStore codeStore;
    private Authentication authenticationToken;
    private UaaUserDatabase userDatabase;
    private ClientServicesExtension clientDetailsService;
    private String clientId;

    @Before
    public void setUp() {
        IdentityZoneHolder.clear();
        clientId = new RandomValueStringGenerator().generate();
        manager = new AutologinAuthenticationManager();
        codeStore = mock(ExpiringCodeStore.class);
        userDatabase = mock(UaaUserDatabase.class);
        clientDetailsService = mock(ClientServicesExtension.class);
        manager.setExpiringCodeStore(codeStore);
        manager.setClientDetailsService(clientDetailsService);
        manager.setUserDatabase(userDatabase);
        Map<String,String> info = new HashMap<>();
        info.put("code", "the_secret_code");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest(), clientId);
        authenticationToken = new AuthzAuthenticationRequest(info, details);
    }

    @Test
    public void authentication_successful() throws Exception {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "test-user-id");
        codeData.put("client_id", clientId);
        codeData.put("username", "test-username");
        codeData.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData), ExpiringCodeType.AUTOLOGIN.name()));

        when(clientDetailsService.loadClientByClientId(eq(clientId), anyString())).thenReturn(new BaseClientDetails("test-client-details","","","",""));
        String zoneId = IdentityZoneHolder.get().getId();
        when(userDatabase.retrieveUserById(eq("test-user-id")))
            .thenReturn(
                new UaaUser("test-user-id",
                            "test-username",
                            "password",
                            "email@email.com",
                            Collections.EMPTY_LIST,
                            "given name",
                            "family name",
                            new Date(System.currentTimeMillis()),
                            new Date(System.currentTimeMillis()),
                            OriginKeys.UAA,
                            "test-external-id",
                            true,
                            zoneId,
                            "test-salt",
                            new Date(System.currentTimeMillis())
                )
            );

        Authentication authenticate = manager.authenticate(authenticationToken);

        assertThat(authenticate, is(instanceOf(UaaAuthentication.class)));
        UaaAuthentication uaaAuthentication = (UaaAuthentication)authenticate;
        assertThat(uaaAuthentication.getPrincipal().getId(), is("test-user-id"));
        assertThat(uaaAuthentication.getPrincipal().getName(), is("test-username"));
        assertThat(uaaAuthentication.getPrincipal().getOrigin(), is(OriginKeys.UAA));
        assertThat(uaaAuthentication.getDetails(), is(instanceOf(UaaAuthenticationDetails.class)));
        UaaAuthenticationDetails uaaAuthDetails = (UaaAuthenticationDetails)uaaAuthentication.getDetails();
        assertThat(uaaAuthDetails.getClientId(), is(clientId));
    }

    @Test(expected = BadCredentialsException.class)
    public void authentication_fails_withInvalidClient() {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "test-user-id");
        codeData.put("client_id", "actual-client-id");
        codeData.put("username", "test-username");
        codeData.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        codeData.put("action", ExpiringCodeType.AUTOLOGIN.name());
        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData), null));

        manager.authenticate(authenticationToken);
    }

    @Test(expected = BadCredentialsException.class)
    public void authentication_fails_withNoClientId() {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "test-user-id");
        codeData.put("username", "test-username");
        codeData.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        codeData.put("action", ExpiringCodeType.AUTOLOGIN.name());
        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData), null));

        manager.authenticate(authenticationToken);
    }

    @Test(expected = InvalidCodeException.class)
    public void authentication_fails_withExpiredCode() {
        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(null);
        manager.authenticate(authenticationToken);
    }

    @Test(expected = InvalidCodeException.class)
    public void authentication_fails_withCodeIntendedForDifferentPurpose() {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "test-user-id");
        codeData.put("client_id", clientId);
        codeData.put("username", "test-username");
        codeData.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData), null));

        manager.authenticate(authenticationToken);
    }

    @Test(expected = InvalidCodeException.class)
    public void authentication_fails_withInvalidCode() {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("action", "someotheraction");
        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(123), JsonUtils.writeValueAsString(codeData), null));

        manager.authenticate(authenticationToken);
    }


}
