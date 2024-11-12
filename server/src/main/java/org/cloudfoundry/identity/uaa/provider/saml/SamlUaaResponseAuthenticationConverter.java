package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.NotANumber;

/**
 * AuthenticationConverter used during SAML login flow to convert a SAML response token to a UaaAuthentication.
 */
@Slf4j
@Getter
public class SamlUaaResponseAuthenticationConverter
        implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, UaaAuthentication>,
        ApplicationEventPublisherAware {

    public static final String AUTHENTICATION_CONTEXT_CLASS_REFERENCE = "acr";

    private final IdentityZoneManager identityZoneManager;

    private final IdentityProviderProvisioning identityProviderProvisioning;

    private ApplicationEventPublisher eventPublisher;

    private final SamlUaaAuthenticationUserManager userManager;
    private final SamlUaaAuthenticationAttributesConverter attributesConverter;
    private final SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter;

    public SamlUaaResponseAuthenticationConverter(IdentityZoneManager identityZoneManager,
                                                  final JdbcIdentityProviderProvisioning identityProviderProvisioning,
                                                  SamlUaaAuthenticationUserManager userManager,
                                                  SamlUaaAuthenticationAttributesConverter attributesConverter,
                                                  SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter) {
        this.identityZoneManager = identityZoneManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.userManager = userManager;
        this.attributesConverter = attributesConverter;
        this.authoritiesConverter = authoritiesConverter;
    }

    @Override
    public UaaAuthentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        Saml2AuthenticationToken authenticationToken = responseToken.getToken();
        Response response = responseToken.getResponse();
        List<Assertion> assertions = response.getAssertions();
        String subjectName = assertions.get(0).getSubject().getNameID().getValue();

        IdentityZone zone = identityZoneManager.getCurrentIdentityZone();
        log.debug("Initiating SAML authentication in zone '{}' domain '{}'",
                zone.getId(), zone.getSubdomain());

        RelyingPartyRegistration relyingPartyRegistration = authenticationToken.getRelyingPartyRegistration();
        String alias = relyingPartyRegistration.getRegistrationId();
        UaaPrincipal initialPrincipal = new UaaPrincipal(NotANumber, subjectName, authenticationToken.getName(),
                alias, authenticationToken.getName(), zone.getId());
        log.debug("Mapped SAML authentication to IDP with origin '{}' and username '{}'",
                alias, initialPrincipal.getName());

        boolean addNew;
        IdentityProvider<SamlIdentityProviderDefinition> idp;
        SamlIdentityProviderDefinition samlConfig;
        try {
            idp = identityProviderProvisioning.retrieveByOrigin(alias, zone.getId());
            samlConfig = idp.getConfig();
            addNew = samlConfig.isAddShadowUserOnLogin();
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator for alias:" + alias);
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("No SAML identity provider found in zone for alias:" + alias);
        }

        MultiValueMap<String, String> userAttributes = attributesConverter.retrieveUserAttributes(samlConfig, response);
        List<? extends GrantedAuthority> samlAuthorities = authoritiesConverter.retrieveSamlAuthorities(samlConfig, response);

        log.debug("Mapped SAML authentication to IDP with origin '{}' and username '{}'",
                idp.getOriginKey(), initialPrincipal.getName());

        UaaUser user = userManager.createIfMissing(initialPrincipal, addNew, getMappedAuthorities(
                idp, samlAuthorities), userAttributes);

        List<String> sessionIndexes = assertions.stream().flatMap(assertion -> assertion.getAuthnStatements().stream().filter(Objects::nonNull).map(s -> s.getSessionIndex()).filter(Objects::nonNull)).toList();
        UaaAuthentication authentication = new UaaAuthentication(
                new UaaSamlPrincipal(user, sessionIndexes),
                authenticationToken.getCredentials(),
                user.getAuthorities(),
                authoritiesConverter.filterSamlAuthorities(samlConfig, samlAuthorities),
                attributesConverter.retrieveCustomUserAttributes(userAttributes),
                null,
                true, System.currentTimeMillis(),
                -1);

        authentication.setAuthenticationMethods(Set.of("ext"));
        setAuthContextClassRef(userAttributes, authentication, samlConfig);

        publish(new IdentityProviderAuthenticationSuccessEvent(user, authentication, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZoneId()));

        if (samlConfig.isStoreCustomAttributes()) {
            userManager.storeCustomAttributesAndRoles(user, authentication);
        }

        AbstractSaml2AuthenticationRequest authenticationRequest = authenticationToken.getAuthenticationRequest();
        if (authenticationRequest != null) {
            String relayState = authenticationRequest.getRelayState();
            configureRelayRedirect(relayState);
        }

        return authentication;
    }

    private static void setAuthContextClassRef(MultiValueMap<String, String> userAttributes,
                                               UaaAuthentication authentication, SamlIdentityProviderDefinition samlConfig) {

        List<String> acrValues = userAttributes.get(AUTHENTICATION_CONTEXT_CLASS_REFERENCE);
        if (acrValues != null) {
            authentication.setAuthContextClassRef(Set.copyOf(acrValues));
        }

        if (samlConfig.getAuthnContext() != null) {
            assert acrValues != null;
            if (Collections.disjoint(acrValues, samlConfig.getAuthnContext())) {
                throw new BadCredentialsException(
                        "Identity Provider did not authenticate with the requested AuthnContext.");
            }
        }
    }

    private Collection<? extends GrantedAuthority> getMappedAuthorities(
            IdentityProvider<SamlIdentityProviderDefinition> idp,
            List<? extends GrantedAuthority> samlAuthorities) {
        Collection<? extends GrantedAuthority> authorities;
        SamlIdentityProviderDefinition.ExternalGroupMappingMode groupMappingMode = idp.getConfig().getGroupMappingMode();
        authorities = switch (groupMappingMode) {
            case EXPLICITLY_MAPPED -> authoritiesConverter.mapAuthorities(idp.getOriginKey(),
                    samlAuthorities, identityZoneManager.getCurrentIdentityZoneId());
            case AS_SCOPES -> List.copyOf(samlAuthorities);
        };
        return authorities;
    }

    public void configureRelayRedirect(String relayState) {
        //configure relay state
        if (UaaUrlUtils.isUrl(relayState)) {
            RequestContextHolder.currentRequestAttributes()
                    .setAttribute(
                            UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE,
                            relayState,
                            RequestAttributes.SCOPE_REQUEST
                    );
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }
}
