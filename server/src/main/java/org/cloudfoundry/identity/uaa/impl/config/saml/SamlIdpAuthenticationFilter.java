/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderHolder;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.IdpInitiatedLoginFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.attribute.AttributeNameFormat;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class SamlIdpAuthenticationFilter extends IdpInitiatedLoginFilter {
    private static Log log = LogFactory.getLog(SamlIdpAuthenticationFilter.class);

    private final SamlServiceProviderProvisioning serviceProviderProvisioning;
    private final SamlServiceProviderConfigurator configurator;
    private JdbcScimUserProvisioning scimUserProvisioning;

    public SamlIdpAuthenticationFilter(SamlProviderProvisioning<IdentityProviderService> provisioning,
                                       SamlMessageStore<Assertion, HttpServletRequest> assertionStore,
                                       SamlRequestMatcher requestMatcher,
                                       SamlServiceProviderProvisioning serviceProviderProvisioning,
                                       JdbcScimUserProvisioning scimUserProvisioning,
                                       SamlServiceProviderConfigurator configurator) {
        super(provisioning, assertionStore, requestMatcher);
        this.serviceProviderProvisioning = serviceProviderProvisioning;
        this.scimUserProvisioning = scimUserProvisioning;
        this.configurator = configurator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        try {
            super.doFilterInternal(request, response, filterChain);
        } catch (ProviderNotFoundException e) {
            response.setStatus(400);
            request.setAttribute("saml_error", e.getMessage());
            request.getRequestDispatcher("/oauth_error").forward(request, response);
        }
    }

    @Override
    protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
        String sp = request.getParameter("sp");
        if (!hasText(sp)) {
            throw new ProviderNotFoundException("Missing sp request parameter. sp parameter must be a valid and configured entity ID");
        }
        log.debug(String.format("IDP is initiating authentication request to SP[%s]", sp));
        Optional<SamlServiceProviderHolder> holder = configurator.getSamlServiceProviders().stream().filter(serviceProvider -> sp.equals(serviceProvider.getSamlServiceProvider().getEntityId())).findFirst();
        if (!holder.isPresent()) {
            log.debug(String.format("SP[%s] was not found, aborting saml response", sp));
            throw new ProviderNotFoundException("Invalid sp entity ID. sp parameter must be a valid and configured entity ID");
        }
        if (!holder.get().getSamlServiceProvider().isActive()) {
            log.debug(String.format("SP[%s] is disabled, aborting saml response", sp));
            throw new ProviderNotFoundException("Service provider is disabled.");
        }
        if (!holder.get().getSamlServiceProvider().getConfig().isEnableIdpInitiatedSso()) {
            log.debug(String.format("SP[%s] initiated login is disabled, aborting saml response", sp));
            throw new ProviderNotFoundException("IDP initiated login is disabled for this service provider.");
        }

        ServiceProviderMetadata provider = super.getTargetProvider(request);
        if (provider == null) {
            log.debug(String.format("SP[%s] was not found, possible metadata failure, aborting saml response", sp));
            throw new ProviderNotFoundException("Invalid sp entity ID. Unable to find valid metadata for sp");
        }
        return provider;
    }

    @Override
    protected Assertion getAssertion(Authentication authentication,
                                     IdentityProviderService provider,
                                     ServiceProviderMetadata recipient) {
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();

        SamlServiceProviderDefinition config =
            serviceProviderProvisioning.retrieveByEntityId(
                recipient.getEntityId(), IdentityZoneHolder.get().getId()
            ).getConfig();

        List<Attribute> attributes = new LinkedList<>();

        Assertion assertion = super.getAssertion(authentication, provider, recipient);

        //groups
        mapGroupsToAttributes(authentication, attributes);
        //pre defined attributes
        mapAuthenticationToAttributes(authentication, attributes);
        //static attributes
        mapStaticAttributes(attributes, config);
        //attribute mappings
        mapConfigurableAttributes(principal, attributes, config);

        return assertion.setAttributes(attributes);
    }

    private void mapConfigurableAttributes(UaaPrincipal principal, List<Attribute> attributes, SamlServiceProviderDefinition config) {
        Map<String, Object> attributeMappings = config.getAttributeMappings();
        if (attributeMappings.size() > 0) {
            ScimUser user = scimUserProvisioning.retrieve(principal.getId(), IdentityZoneHolder.get().getId());

            String givenName = user.getGivenName();
            if (hasText(givenName) && attributeMappings.containsKey("given_name")) {
                Attribute givenNameAttribute = buildStringAttribute(attributeMappings.get("given_name").toString(), Collections.singletonList(givenName));
                attributes.add(givenNameAttribute);
            }

            String familyName = user.getFamilyName();
            if (hasText(familyName) && attributeMappings.containsKey("family_name")) {
                Attribute familyNameAttribute = buildStringAttribute(attributeMappings.get("family_name").toString(), Collections.singletonList(familyName));
                attributes.add(familyNameAttribute);
            }

            String phoneNumber = scimUserProvisioning.extractPhoneNumber(user);
            if (hasText(phoneNumber) && attributeMappings.containsKey("phone_number")) {
                Attribute phoneNumberAttribute = buildStringAttribute(attributeMappings.get("phone_number").toString(), Collections.singletonList(phoneNumber));
                attributes.add(phoneNumberAttribute);
            }

            String email = user.getPrimaryEmail();
            if (hasText(email) && attributeMappings.containsKey("email")) {
                Attribute customEmailAttribute = buildStringAttribute(attributeMappings.get("email").toString(), Collections.singletonList(email));
                attributes.add(customEmailAttribute);
            }
        }
    }

    private void mapStaticAttributes(List<Attribute> attributes, SamlServiceProviderDefinition config) {
        for (Map.Entry<String,Object> staticAttribute :
            (ofNullable(config.getStaticCustomAttributes()).orElse(Collections.emptyMap())).entrySet())
        {
            String name = staticAttribute.getKey();
            Object value = staticAttribute.getValue();
            if (value==null) {
                continue;
            }

            List values = new LinkedList<>();
            if (value instanceof List) {
                values = (List) value;
            } else {
                values.add(value);
            }

            List<Object> stringValues =
                (List<Object>) values.stream()
                    .map(s -> s==null ? "null" : s.toString()).collect(Collectors.toList());
            attributes.add(buildStringAttribute(name, stringValues));
        }
    }

    private void mapAuthenticationToAttributes(Authentication authentication, List<Attribute> attributes) {
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        attributes.add(buildStringAttribute("email", principal.getEmail()));
        attributes.add(buildStringAttribute("id", principal.getId()));
        attributes.add(buildStringAttribute("name", principal.getName()));
        attributes.add(buildStringAttribute("origin", principal.getOrigin()));
        attributes.add(buildStringAttribute("zoneId", principal.getZoneId()));
    }

    private void mapGroupsToAttributes(Authentication authentication, List<Attribute> attributes) {
        //groups
        List<Object> authorities =
            authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        Attribute groups = new Attribute()
            .setNameFormat(AttributeNameFormat.BASIC)
            .setName("authorities")
            .setFriendlyName("authorities")
            .setValues(authorities);
        attributes.add(groups);
    }

    private Attribute buildStringAttribute(String name, String value) {
        return buildStringAttribute(name, Collections.singletonList(value));
    }

    private Attribute buildStringAttribute(String name, List<Object> value) {
        return new Attribute()
            .setNameFormat(AttributeNameFormat.BASIC)
            .setName(name)
            .setFriendlyName(name)
            .setValues(value);
    }
}
