package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(PollutionPreventionExtension.class)
class IdentityProviderModifiedEventTest {

    private IdentityProvider<SamlIdentityProviderDefinition> provider;
    private String currentIdentityZoneId;

    @BeforeEach
    void setup() {
        final RandomValueStringGenerator randomValueStringGenerator = new RandomValueStringGenerator();
        currentIdentityZoneId = "currentIdentityZoneId-" + randomValueStringGenerator.generate();

        String origin = "idp-mock-saml-" + randomValueStringGenerator.generate();
        String metadata = String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://localhost:9999/metadata/" + origin);
        provider = new IdentityProvider<>();
        provider.setId("id");
        provider.setActive(true);
        provider.setName(origin);
        provider.setType(OriginKeys.SAML);
        provider.setIdentityZoneId(currentIdentityZoneId);
        provider.setOriginKey(origin);
        SamlIdentityProviderDefinition samlDefinition =
                new SamlIdentityProviderDefinition()
                        .setMetaDataLocation(metadata)
                        .setLinkText("Test SAML Provider");
        samlDefinition.setEmailDomain(Arrays.asList("test.com", "test2.com"));
        List<String> externalGroupsWhitelist = new ArrayList<>();
        externalGroupsWhitelist.add("value");
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        samlDefinition.setExternalGroupsWhitelist(externalGroupsWhitelist);
        samlDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(samlDefinition);
    }

    @Test
    void identityProviderCreated() {
        IdentityProviderModifiedEvent identityProviderCreatedEvent = IdentityProviderModifiedEvent.identityProviderCreated(provider, currentIdentityZoneId);
        evaluateEventString(identityProviderCreatedEvent, provider);
    }

    @Test
    void identityProviderModified() {
        IdentityProviderModifiedEvent identityProviderModifiedEvent = IdentityProviderModifiedEvent.identityProviderModified(provider, currentIdentityZoneId);
        evaluateEventString(identityProviderModifiedEvent, provider);
    }

    static void evaluateEventString(
            final IdentityProviderModifiedEvent event,
            final IdentityProvider<SamlIdentityProviderDefinition> provider) {
        assertEquals(
                String.format(IdentityProviderModifiedEvent.dataFormat,
                        provider.getId(),
                        provider.getType(),
                        provider.getOriginKey(),
                        provider.getIdentityZoneId()),
                event.getAuditEvent().getData());
    }

}