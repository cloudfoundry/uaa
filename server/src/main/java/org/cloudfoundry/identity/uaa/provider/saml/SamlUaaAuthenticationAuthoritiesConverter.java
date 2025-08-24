package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Optional.of;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.saml.OpenSamlXmlUtils.getStringValue;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.retainAllMatches;

/**
 * Part of the AuthenticationConverter used during SAML login flow.
 * This handles the conversion of SAML Authorities to UAA Authorities.
 */
@Slf4j
@Getter
public class SamlUaaAuthenticationAuthoritiesConverter {

    private final ScimGroupExternalMembershipManager externalMembershipManager;

    public SamlUaaAuthenticationAuthoritiesConverter(
            ScimGroupExternalMembershipManager externalMembershipManager) {
        this.externalMembershipManager = externalMembershipManager;
    }

    protected Set<String> filterSamlAuthorities(SamlIdentityProviderDefinition definition, Collection<? extends GrantedAuthority> samlAuthorities) {
        List<String> whiteList = of(definition.getExternalGroupsWhitelist()).orElse(List.of());
        Set<String> authorities = samlAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        if (whiteList.isEmpty()) {
            return authorities;
        }
        Set<String> result = retainAllMatches(authorities, whiteList);
        log.debug("White listed external SAML groups:'{}'", result);
        return result;
    }

    protected Collection<SamlUserAuthority> mapAuthorities(String origin, Collection<? extends GrantedAuthority> authorities, String identityZoneId) {
        Collection<SamlUserAuthority> result = new LinkedList<>();
        log.debug("Mapping SAML authorities:{}", authorities);
        for (GrantedAuthority authority : authorities) {
            String externalGroup = authority.getAuthority();
            log.debug("Attempting to map external group: {}", externalGroup);
            for (ScimGroupExternalMember internalGroup : externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup, origin, identityZoneId)) {
                String internalName = internalGroup.getDisplayName();
                log.debug("Mapped external: '{}' to internal: '{}'", externalGroup, internalName);
                result.add(new SamlUserAuthority(internalName));
            }
        }
        return result;
    }

    protected List<SamlUserAuthority> retrieveSamlAuthorities(SamlIdentityProviderDefinition definition, List<Assertion> assertions) {
        if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) != null) {
            List<String> groupAttributeNames = getGroupAttributeNames(definition);

            List<SamlUserAuthority> authorities = new ArrayList<>();
            assertions.stream().flatMap(assertion -> assertion.getAttributeStatements().stream())
                    .flatMap(attributeStatement -> attributeStatement.getAttributes().stream())
                    .filter(attribute -> groupAttributeNames.contains(attribute.getName()) || groupAttributeNames.contains(attribute.getFriendlyName()))
                    .filter(attribute -> attribute.getAttributeValues() != null)
                    .filter(attribute -> !attribute.getAttributeValues().isEmpty())
                    .forEach(attribute -> {
                        for (XMLObject group : attribute.getAttributeValues()) {
                            authorities.add(new SamlUserAuthority(getStringValue(attribute.getName(),
                                    definition,
                                    group)));
                        }
                    });

            return authorities;
        }
        return new ArrayList<>();
    }

    private List<String> getGroupAttributeNames(SamlIdentityProviderDefinition definition) {
        List<String> attributeNames = new LinkedList<>();

        if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof String value) {
            attributeNames.add(value);
        } else if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof Collection<?> value) {
            attributeNames.addAll((Collection<String>) value);
        }
        return attributeNames;
    }
}
