package org.cloudfoundry.identity.uaa.login;

import org.springframework.context.annotation.Bean;
import org.springframework.web.accept.ContentNegotiationManager;

public class ThymeleafAdditional {

    @Bean
    public ContentNegotiationManager contentNegotiationManager() {
        return new ContentNegotiationManager();
    }
}
