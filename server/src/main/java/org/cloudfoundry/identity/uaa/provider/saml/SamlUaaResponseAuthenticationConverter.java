package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Objects;

/**
 * AuthenticationConverter used during SAML login flow to convert a SAML response token to a UaaAuthentication.
 */
@Slf4j
@Getter
public class SamlUaaResponseAuthenticationConverter
        implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, UaaAuthentication>,
        ApplicationEventPublisherAware {

    private final IdentityZoneManager identityZoneManager;

    private ApplicationEventPublisher eventPublisher;

    private final SamlUaaAuthenticationUserManager userManager;

    public SamlUaaResponseAuthenticationConverter(IdentityZoneManager identityZoneManager,
            SamlUaaAuthenticationUserManager userManager) {
        this.identityZoneManager = identityZoneManager;
        this.userManager = userManager;
    }

    @Override
    public UaaAuthentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        Saml2AuthenticationToken authenticationToken = responseToken.getToken();
        Response response = responseToken.getResponse();
        List<Assertion> assertions = response.getAssertions();
        List<String> subjectNameList = assertions.stream().filter(Objects::nonNull).map(assertion -> assertion.getSubject().getNameID().getValue()).toList();
        if (ObjectUtils.isEmpty(subjectNameList) || subjectNameList.size() != 1) {
            throw new BadCredentialsException("SAML response does not contain a subject name");
        }

        IdentityZone zone = identityZoneManager.getCurrentIdentityZone();
        log.debug("Initiating SAML authentication in zone '{}' domain '{}'",
                zone.getId(), zone.getSubdomain());

        RelyingPartyRegistration relyingPartyRegistration = authenticationToken.getRelyingPartyRegistration();
        String alias = relyingPartyRegistration.getRegistrationId();
        List<String> sessionIndexes = assertions.stream().flatMap(assertion -> assertion.getAuthnStatements().stream().filter(Objects::nonNull).map(AuthnStatement::getSessionIndex).filter(Objects::nonNull)).toList();
        return userManager.getUaaAuthentication(subjectNameList.getFirst(), authenticationToken, alias, assertions, sessionIndexes);
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
