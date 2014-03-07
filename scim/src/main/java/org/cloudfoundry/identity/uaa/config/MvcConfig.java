package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.scim.endpoints.ScimEtagHandlerMethodReturnValueHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodReturnValueHandler;
import org.springframework.web.method.support.HandlerMethodReturnValueHandlerComposite;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestResponseBodyMethodProcessor;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class MvcConfig extends WebMvcConfigurationSupport {

    @Autowired
    private ApplicationContext applicationContext;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**").addResourceLocations("/");
    }

    @Override
    public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }

    @Override
    public RequestMappingHandlerAdapter requestMappingHandlerAdapter() {
        RequestMappingHandlerAdapter requestMappingHandlerAdapter = super.requestMappingHandlerAdapter();
        requestMappingHandlerAdapter.setApplicationContext(applicationContext);
        requestMappingHandlerAdapter.setOrder(0);
        requestMappingHandlerAdapter.afterPropertiesSet();
        installScimEtagHandlerMethodReturnValueHandler(requestMappingHandlerAdapter);
        return requestMappingHandlerAdapter;
    }

    private void installScimEtagHandlerMethodReturnValueHandler(RequestMappingHandlerAdapter requestMappingHandlerAdapter) {
        HandlerMethodReturnValueHandlerComposite handlerComposite = requestMappingHandlerAdapter.getReturnValueHandlers();
        List<HandlerMethodReturnValueHandler> handlers = new ArrayList<HandlerMethodReturnValueHandler>(handlerComposite.getHandlers());
        int i;
        for (i = 0; i < handlers.size(); i++) {
            HandlerMethodReturnValueHandler handler = handlers.get(i);
            if (handler.getClass().isAssignableFrom(RequestResponseBodyMethodProcessor.class)) {
                break;
            }
        }
        handlers.remove(i);
        ScimEtagHandlerMethodReturnValueHandler scimEtagHandlerMethodReturnValueHandler = new ScimEtagHandlerMethodReturnValueHandler(requestMappingHandlerAdapter.getMessageConverters());
        handlers.add(i, scimEtagHandlerMethodReturnValueHandler);
        requestMappingHandlerAdapter.setReturnValueHandlers(handlers);
    }
}
