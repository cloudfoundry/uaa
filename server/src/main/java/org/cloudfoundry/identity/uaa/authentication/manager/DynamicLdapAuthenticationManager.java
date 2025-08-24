package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.EnvironmentPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.LdapUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.nio.file.ProviderNotFoundException;

public class DynamicLdapAuthenticationManager implements AuthenticationManager {
    private final LdapIdentityProviderDefinition definition;
    private ClassPathXmlApplicationContext context;
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final LdapLoginAuthenticationManager ldapLoginAuthenticationManager;
    private AuthenticationManager manager;
    private AuthenticationManager ldapManagerActual;
    private ApplicationEventPublisher eventPublisher;


    public DynamicLdapAuthenticationManager(LdapIdentityProviderDefinition definition,
            ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
            ScimGroupProvisioning scimGroupProvisioning,
            LdapLoginAuthenticationManager ldapLoginAuthenticationManager) {
        this.definition = definition;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.ldapLoginAuthenticationManager = ldapLoginAuthenticationManager;
    }

    public ClassPathXmlApplicationContext getContext() {
        return context;
    }

    public synchronized AuthenticationManager getLdapAuthenticationManager() throws BeansException {
        if (definition == null) {
            return null;
        }
        if (manager != null) {
            return manager;
        }
        if (context == null) {
            ConfigurableEnvironment environment = LdapUtils.getLdapConfigurationEnvironment(definition);
            //create parent BeanFactory to inject singletons from the parent
            DefaultListableBeanFactory parentBeanFactory = new DefaultListableBeanFactory();
            parentBeanFactory.registerSingleton("externalGroupMembershipManager", scimGroupExternalMembershipManager);
            parentBeanFactory.registerSingleton("scimGroupProvisioning", scimGroupProvisioning);
            parentBeanFactory.registerSingleton("ldapLoginAuthenticationMgr", ldapLoginAuthenticationManager);
            GenericApplicationContext parent = new GenericApplicationContext(parentBeanFactory);
            parent.refresh();

            //create the context that holds LDAP
            context = new ClassPathXmlApplicationContext(new String[]{"ldap-integration.xml"}, false, parent);
            context.setEnvironment(environment);
            EnvironmentPropertiesFactoryBean factoryBean = new EnvironmentPropertiesFactoryBean();
            factoryBean.setEnvironment(environment);
            PropertySourcesPlaceholderConfigurer placeholderConfigurer = new PropertySourcesPlaceholderConfigurer();
            placeholderConfigurer.setProperties(factoryBean.getObject());
            placeholderConfigurer.setLocalOverride(true);
            context.addBeanFactoryPostProcessor(placeholderConfigurer);
            context.refresh();
            ldapManagerActual = (AuthenticationManager) context.getBean("ldapAuthenticationManager");
            AuthenticationManager shadowUserManager = (AuthenticationManager) context.getBean("ldapLoginAuthenticationMgr");

            //chain the LDAP with the shadow account creation manager
            ChainedAuthenticationManager chainedAuthenticationManager = new ChainedAuthenticationManager();
            ChainedAuthenticationManager.AuthenticationManagerConfiguration config1 =
                    new ChainedAuthenticationManager.AuthenticationManagerConfiguration(ldapManagerActual, null);
            ChainedAuthenticationManager.AuthenticationManagerConfiguration config2 =
                    new ChainedAuthenticationManager.AuthenticationManagerConfiguration(shadowUserManager, "ifPreviousTrue");
            chainedAuthenticationManager.setDelegates(new ChainedAuthenticationManager.AuthenticationManagerConfiguration[]{config1, config2});
            manager = chainedAuthenticationManager;
        }

        return manager;
    }

    public AuthenticationManager getLdapManagerActual() {
        return ldapManagerActual;
    }

    public LdapIdentityProviderDefinition getDefinition() {
        return definition;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthenticationManager manager = getLdapAuthenticationManager();
        if (manager != null) {
            try {
                return manager.authenticate(authentication);
            } catch (BadCredentialsException e) {
                publish(new IdentityProviderAuthenticationFailureEvent(authentication, authentication.getName(), OriginKeys.LDAP, IdentityZoneHolder.getCurrentZoneId()));
                throw e;
            }
        }
        throw new ProviderNotFoundException("LDAP provider not configured");
    }

    public void destroy() {
        ClassPathXmlApplicationContext applicationContext = context;
        if (applicationContext != null) {
            context = null;
            applicationContext.close();
        }
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }
}
