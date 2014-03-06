package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.scim.endpoints.ScimEtagHandlerMethodReturnValueHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.method.support.HandlerMethodReturnValueHandler;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.util.List;

@EnableWebMvc
@Configuration
public class WebMvcConfig extends WebMvcConfigurerAdapter{

    @Override
    public void addReturnValueHandlers(List<HandlerMethodReturnValueHandler> returnValueHandlers) {
        returnValueHandlers.add(0, new ScimEtagHandlerMethodReturnValueHandler(new RestTemplate().getMessageConverters()));
        super.addReturnValueHandlers(returnValueHandlers);
    }
}
