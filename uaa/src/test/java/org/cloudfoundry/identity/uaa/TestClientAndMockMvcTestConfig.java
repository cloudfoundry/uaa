package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.test.TestClient;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.DispatcherType;

@Configuration
public class TestClientAndMockMvcTestConfig {
    @Bean
    public MockMvc mockMvc(
            WebApplicationContext webApplicationContext,
            @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") FilterChainProxy springSecurityFilterChain,
            SessionRepositoryFilter springSessionRepositoryFilter
    ) {


        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(springSessionRepositoryFilter);
        filterRegistrationBean.addUrlPatterns("/*");
        filterRegistrationBean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ERROR);
        //    <filter-mapping>
//        <filter-name>springSessionRepositoryFilter</filter-name>
//        <url-pattern>/*</url-pattern>
//        <dispatcher>REQUEST</dispatcher>
//        <dispatcher>ERROR</dispatcher>
//    </filter-mapping>




        return MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .addFilter(new DelegatingFilterProxy(filterRegistrationBean.getFilter()))
                .build();
    }

    @Bean
    public TestClient testClient(
            MockMvc mockMvc
    ) {
        return new TestClient(mockMvc);
    }
}
