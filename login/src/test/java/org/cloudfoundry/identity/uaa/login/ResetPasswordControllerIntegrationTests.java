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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.login.test.UaaRestTemplateBeanFactoryPostProcessor;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ResetPasswordControllerIntegrationTests {

    XmlWebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private MockRestServiceServer mockUaaServer;

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.addBeanFactoryPostProcessor(new UaaRestTemplateBeanFactoryPostProcessor());
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();

        mockUaaServer = MockRestServiceServer.createServer(webApplicationContext.getBean("authorizationTemplate", RestTemplate.class));
    }

    @Test
    public void testResettingAPassword() throws Exception {
        mockUaaServer.expect(requestTo("http://localhost:8080/uaa/password_change"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.code").value("the_secret_code"))
            .andExpect(jsonPath("$.new_password").value("secret"))
            .andRespond(withSuccess("{" +
                "\"user_id\":\"newly-created-user-id\"," +
                "\"username\":\"user@example.com\"" +
                "}", APPLICATION_JSON));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", "the_secret_code")
            .param("email", "user@example.com")
            .param("password", "secret")
            .param("password_confirmation", "secret");

        MvcResult mvcResult = mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("home"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getId(), equalTo("newly-created-user-id"));
        Assert.assertThat(principal.getName(), equalTo("user@example.com"));
        Assert.assertThat(principal.getEmail(), equalTo("user@example.com"));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }
}
