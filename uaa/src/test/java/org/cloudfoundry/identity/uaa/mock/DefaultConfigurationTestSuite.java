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
package org.cloudfoundry.identity.uaa.mock;

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.login.AccountsControllerMockMvcTests;
import org.cloudfoundry.identity.uaa.login.LoginMockMvcTests;
import org.cloudfoundry.identity.uaa.login.PasscodeMockMvcTests;
import org.cloudfoundry.identity.uaa.login.ResetPasswordControllerMockMvcTests;
import org.cloudfoundry.identity.uaa.login.XFrameOptionsTheories;
import org.cloudfoundry.identity.uaa.login.saml.SamlIDPRefreshMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.audit.AuditCheckMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.clients.ClientAdminEndpointsMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.codestore.ExpiringCodeStoreMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.config.HealthzShouldNotBeProtectedMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.oauth.CheckDefaultAuthoritiesMvcMockTests;
import org.cloudfoundry.identity.uaa.mock.token.TokenKeyEndpointMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.token.TokenMvcMockTests;
import org.cloudfoundry.identity.uaa.mock.zones.IdentityProviderEndpointsMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.zones.IdentityZoneEndpointsMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.zones.IdentityZoneSwitchingFilterMockMvcTest;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpointsMockMvcTests;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpointsMockMvcTests;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpointsMockMvcTests;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserLookupMockMvcTests;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

@RunWith(UaaJunitSuiteRunner.class)
@Suite.SuiteClasses({
    XFrameOptionsTheories.class,
    TokenKeyEndpointMockMvcTests.class,
    IdentityProviderEndpointsMockMvcTests.class,
    IdentityZoneEndpointsMockMvcTests.class,
    IdentityZoneSwitchingFilterMockMvcTest.class,
    AuditCheckMockMvcTests.class,
    ClientAdminEndpointsMockMvcTests.class,
    ExpiringCodeStoreMockMvcTests.class,
    CheckDefaultAuthoritiesMvcMockTests.class,
    TokenMvcMockTests.class,
    ResetPasswordControllerMockMvcTests.class,
    PasswordResetEndpointsMockMvcTests.class,
    ScimGroupEndpointsMockMvcTests.class,
    ScimUserEndpointsMockMvcTests.class,
    ScimUserLookupMockMvcTests.class,
    HealthzShouldNotBeProtectedMockMvcTests.class,
    PasscodeMockMvcTests.class,
    AccountsControllerMockMvcTests.class,
    LoginMockMvcTests.class,
    SamlIDPRefreshMockMvcTests.class,
})
public class DefaultConfigurationTestSuite extends UaaBaseSuite {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;

    @BeforeClass
    public static void setUpContextVoid() throws Exception {
        setUpContext();
    }
    public static Object[] setUpContext() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        MockEnvironment mockEnvironment = new MockEnvironment();
        mockEnvironment.setProperty("login.invitationsEnabled", "true");
        webApplicationContext.setEnvironment(mockEnvironment);
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
        return new Object[] {webApplicationContext, mockMvc};
    }

    @AfterClass
    public static void destroyMyContext() throws Exception {
        webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
        webApplicationContext = null;
        mockMvc = null;
    }

}
