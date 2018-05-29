package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public abstract class AbstractExternalLoginAuthenticationManagerBuilder <BuilderType extends AbstractExternalLoginAuthenticationManagerBuilder>{
    // defaults
    boolean enforceDomains = false;
    boolean addShadowUser = true;
    boolean storeCustomAttributes = true;
    List<String> emailDomain;

    String origin = "default_origin";
    IdentityProviderProvisioning idProviderProvisioning;
    IdentityProvider identityProvider;
    ExternalIdentityProviderDefinition providerDefinition;
    UaaUserDatabase uaaUserDatabase = mock(UaaUserDatabase.class);
    List<UaaUser> uaaUsers = new ArrayList<>();
    List<UaaUser> initiallyMissingUaaUsers = new ArrayList<>();
    ApplicationEventPublisher applicationEventPublisher = null;



    protected abstract BuilderType me();

    public BuilderType withProvider(IdentityProvider identityProvider) {
        this.identityProvider = identityProvider;
        return me();
    }

    public BuilderType enforceDomains(boolean enforceDomains) {
        this.enforceDomains = enforceDomains;
        return me();
    }

    public BuilderType addShadowUser(boolean addShadowUser) {
        this.addShadowUser = addShadowUser;
        return me();
    }

    public BuilderType withIdProviderProvisioning(IdentityProviderProvisioning idProviderProvisioning) {
        this.idProviderProvisioning = idProviderProvisioning;
        return me();
    }

    public BuilderType withOrigin(String origin) {
        this.origin = origin;
        return me();
    }

    public BuilderType withProviderDefinition(ExternalIdentityProviderDefinition providerDefinition) {
        this.providerDefinition = providerDefinition;
        return me();
    }

    protected ExternalLoginAuthenticationManager build(ExternalLoginAuthenticationManager manager) {
        if (idProviderProvisioning != null) {
            when(idProviderProvisioning.retrieveByOrigin(eq(origin), anyString())).thenReturn(identityProvider);
        }
        when(identityProvider.getConfig()).thenReturn(providerDefinition);

        when(providerDefinition.isEnforceDomains()).thenReturn(enforceDomains);
        when(providerDefinition.isAddShadowUserOnLogin()).thenReturn(addShadowUser);
        when(providerDefinition.isStoreCustomAttributes()).thenReturn(storeCustomAttributes);
        when(providerDefinition.getEmailDomain()).thenReturn(emailDomain);

        manager.setUserDatabase(uaaUserDatabase);
        manager.setOrigin(origin);
        manager.setApplicationEventPublisher(applicationEventPublisher);
        for (UaaUser uaaUser : uaaUsers) {
            when(uaaUserDatabase.retrieveUserById(eq(uaaUser.getId()))).thenReturn(uaaUser);
            when(uaaUserDatabase.retrieveUserByName(eq(uaaUser.getUsername()), eq(origin))).thenReturn(uaaUser);
        }

        for (UaaUser uaaUser : initiallyMissingUaaUsers) {
            when(uaaUserDatabase.retrieveUserById(eq(uaaUser.getId()))).thenReturn(uaaUser);
            when(uaaUserDatabase.retrieveUserByName(eq(uaaUser.getUsername()), eq(origin)))
                    .thenReturn(null)
                    .thenReturn(uaaUser);
        }

        return manager;
    }

    <T extends ExternalLoginAuthenticationManager> T buildManagerType(Class<T> managerType) {
        try {
            Constructor<T> constructor = managerType.getConstructor(IdentityProviderProvisioning.class);
            T manager = constructor.newInstance(idProviderProvisioning);
            build(manager);
            return manager;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public BuilderType withUaaUserDB(UaaUserDatabase userDb) {
        this.uaaUserDatabase = userDb;
        return me();
    }

    public BuilderType withUaaUser(UaaUser user) {
        uaaUsers.add(user);
        return me();
    }

    public BuilderType withUaaUser(UaaUserBuilder uaaUserBuilder) {
        uaaUsers.add(uaaUserBuilder.build());
        return me();
    }

    /**
     * user visible only after the 1st call to retrieveUserByName.
     * user is always visible for other retreive calls.
     * @param uaaUserBuilder
     * @return
     */
    public BuilderType withInitiallyMissingUaaUser(UaaUserBuilder uaaUserBuilder) {
        initiallyMissingUaaUsers.add(uaaUserBuilder.build());
        return me();
    }

    public BuilderType withApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.applicationEventPublisher = publisher;
        return me();
    }

    public BuilderType storeCustomAttributes(boolean storeCustomAttributes) {
        this.storeCustomAttributes = storeCustomAttributes;
        return me();
    }

    public BuilderType withEmailDomain(List<String> emailDomains) {
        this.emailDomain = emailDomains;
        return me();
    }
}
