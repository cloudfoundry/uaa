package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.config.EnvironmentPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.nio.file.ProviderNotFoundException;

public class DynamicLdapAuthenticationManager implements AuthenticationManager {
    private final LdapIdentityProviderDefinition definition;
    private ClassPathXmlApplicationContext context = null;
    private ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private ScimGroupProvisioning scimGroupProvisioning;
    private LdapLoginAuthenticationManager ldapLoginAuthenticationManager;
    private AuthenticationManager manager;

    public DynamicLdapAuthenticationManager(LdapIdentityProviderDefinition definition,
                                            ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
                                            ScimGroupProvisioning scimGroupProvisioning,
                                            LdapLoginAuthenticationManager ldapLoginAuthenticationManager) {
        this.definition = definition;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.ldapLoginAuthenticationManager = ldapLoginAuthenticationManager;
    }

    public synchronized AuthenticationManager getLdapAuthenticationManager() throws BeansException {
        if (definition==null) {
            return null;
        }
        if (manager!=null) {
            return manager;
        }
        if (context==null) {
            ConfigurableEnvironment environment = definition.getLdapConfigurationEnvironment();
            //create parent BeanFactory to inject singletons from the parent
            DefaultListableBeanFactory parentBeanFactory = new DefaultListableBeanFactory();
            parentBeanFactory.registerSingleton("externalGroupMembershipManager", scimGroupExternalMembershipManager);
            parentBeanFactory.registerSingleton("scimGroupProvisioning", scimGroupProvisioning);
            parentBeanFactory.registerSingleton("ldapLoginAuthenticationMgr", ldapLoginAuthenticationManager);
            GenericApplicationContext parent = new GenericApplicationContext(parentBeanFactory);
            parent.refresh();

            //create the context that holds LDAP
            context = new ClassPathXmlApplicationContext(new String[] {"ldap-integration.xml"}, false, parent);
            context.setEnvironment(environment);
            EnvironmentPropertiesFactoryBean factoryBean = new EnvironmentPropertiesFactoryBean();
            factoryBean.setEnvironment(environment);
            PropertySourcesPlaceholderConfigurer placeholderConfigurer = new PropertySourcesPlaceholderConfigurer();
            placeholderConfigurer.setProperties(factoryBean.getObject());
            placeholderConfigurer.setLocalOverride(true);
            context.addBeanFactoryPostProcessor(placeholderConfigurer);
            context.refresh();
            AuthenticationManager ldapActualManager = (AuthenticationManager)context.getBean("ldapAuthenticationManager");
            AuthenticationManager shadowUserManager = (AuthenticationManager)context.getBean("ldapLoginAuthenticationMgr");

            //chain the LDAP with the shadow account creation manager
            ChainedAuthenticationManager chainedAuthenticationManager = new ChainedAuthenticationManager();
            ChainedAuthenticationManager.AuthenticationManagerConfiguration config1 =
                new ChainedAuthenticationManager.AuthenticationManagerConfiguration(ldapActualManager, null);
            ChainedAuthenticationManager.AuthenticationManagerConfiguration config2 =
                new ChainedAuthenticationManager.AuthenticationManagerConfiguration(shadowUserManager, "ifPreviousTrue");
            chainedAuthenticationManager.setDelegates(new ChainedAuthenticationManager.AuthenticationManagerConfiguration[] {config1, config2});
            manager = chainedAuthenticationManager;
        }

        return manager;
    }

    public LdapIdentityProviderDefinition getDefinition() {
        return definition;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthenticationManager manager = getLdapAuthenticationManager();
        if (manager!=null) {
            return manager.authenticate(authentication);
        }
        throw new ProviderNotFoundException("LDAP provider not configured");
    }

    public void destroy() {
        ClassPathXmlApplicationContext applicationContext = context;
        if (applicationContext != null) {
            context = null;
            applicationContext.destroy();
        }
    }

}
