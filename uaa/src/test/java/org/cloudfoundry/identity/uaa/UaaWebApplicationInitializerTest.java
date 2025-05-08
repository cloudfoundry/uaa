package org.cloudfoundry.identity.uaa;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.StandardServletEnvironment;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import java.util.EventListener;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UaaWebApplicationInitializerTest {
    private UaaWebApplicationInitializer initializer;
    private ConfigurableWebApplicationContext context;
    private StandardServletEnvironment environment;
    private ServletContext servletContext;

    private FilterRegistration.Dynamic filterRegistration;

    private ServletRegistration.Dynamic servletRegistration;


    @BeforeEach
    void setup() {
        initializer = new UaaWebApplicationInitializer();
        context = mock(ConfigurableWebApplicationContext.class);
        environment = new StandardServletEnvironment();
        servletContext = mock(ServletContext.class);


        when(context.getServletContext()).thenReturn(servletContext);
        when(context.getEnvironment()).thenReturn(environment);
        Mockito.doAnswer((Answer<Void>) invocation -> {
            System.err.println(invocation.getArguments()[0]);
            return null;
        }).when(servletContext).log(anyString());
        when(servletContext.getContextPath()).thenReturn("/context");

        filterRegistration = mock(FilterRegistration.Dynamic.class);
        when(servletContext.addFilter(anyString(), ArgumentMatchers.any(javax.servlet.Filter.class)))
                .thenReturn(filterRegistration);

        servletRegistration = mock(ServletRegistration.Dynamic.class);
        when(servletContext.addServlet(anyString(), ArgumentMatchers.any(javax.servlet.Servlet.class)))
                .thenReturn(servletRegistration);

    }

    @Test
    void testServletContextListeners() throws ServletException {
        initializer.onStartup(servletContext);

        ArgumentCaptor<EventListener> listenerArgumentCaptor = ArgumentCaptor.forClass(EventListener.class);
        verify(servletContext, atLeastOnce()).addListener(listenerArgumentCaptor.capture());
        List<EventListener> listeners = listenerArgumentCaptor.getAllValues();
        assertThat(listeners).isNotNull();
        assertThat(listeners.size()).isEqualTo(2);
        assertThat(listeners.get(0)).isInstanceOf(HttpSessionEventPublisher.class);
        assertThat(listeners.get(1)).isInstanceOf(ContextLoaderListener.class);
    }

}