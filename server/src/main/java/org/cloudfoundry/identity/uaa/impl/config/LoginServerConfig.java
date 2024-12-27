package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.NotificationsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class LoginServerConfig {

    @Bean
    public MessageService messageService(EmailService emailService, NotificationsService notificationsService, Environment environment) {
        if (environment.getProperty("notifications.url") != null && !"".equals(environment.getProperty("notifications.url"))) {
            return notificationsService;
        } else {
            return emailService;
        }
    }
}
