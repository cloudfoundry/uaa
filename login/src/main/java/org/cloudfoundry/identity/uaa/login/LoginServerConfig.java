package org.cloudfoundry.identity.uaa.login;

import org.springframework.context.annotation.*;
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
    @Conditional(InviteUsersCondition.class)
    public InvitationsController invitationsController(InvitationsService invitationsService) {
        return new InvitationsController(invitationsService);
    }

    public static class InviteUsersCondition implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return "true".equalsIgnoreCase(context.getEnvironment().getProperty("login.invitationsEnabled"));
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
