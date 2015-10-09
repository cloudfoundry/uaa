package org.cloudfoundry.identity.uaa.login;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

@Configuration
public class LoginServerConfig {

    @Bean
    @Conditional(CreateAccountCondition.class)
    public AccountsController accountsController(AccountCreationService accountCreationService) {
        return new AccountsController(accountCreationService);
    }

    public static class CreateAccountCondition implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return !"false".equalsIgnoreCase(context.getEnvironment().getProperty("login.selfServiceLinksEnabled"));
        }
    }

    @Bean
    public MessageService messageService(EmailService emailService, NotificationsService notificationsService, Environment environment) {
        if (environment.getProperty("notifications.url") != null && !environment.getProperty("notifications.url").equals("")) {
            return notificationsService;
        }
        else {
            return emailService;
        }
    }
}
