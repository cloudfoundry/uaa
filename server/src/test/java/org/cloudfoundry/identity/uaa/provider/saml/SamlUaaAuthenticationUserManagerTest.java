package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.LinkedMultiValueMap;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;

class SamlUaaAuthenticationUserManagerTest {

    private static final String TEST_USERNAME = "test@saml.user";
    private static final String ZONE_ID = "uaa";
    private final UaaUser existing = createUaaUser(TEST_USERNAME);

    private UaaUser createUaaUser(String username) {
        return new UaaUser(username, "", "john.doe@example.com", "John", "Doe");
    }

    @Test
    void haveAttributesChangedReturnsFalseForCopied() {
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing));
        assertThat(SamlUaaAuthenticationUserManager.haveUserAttributesChanged(existing, modified)).isFalse();
    }

    @Test
    void haveAttributesChangedReturnsTrueForChangedEmail() {
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing).withEmail("other-email"));
        assertThat(SamlUaaAuthenticationUserManager.haveUserAttributesChanged(existing, modified)).as("email modified").isTrue();
    }

    @Test
    void haveAttributesChangedReturnsTrueForChangedPhone() {
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing).withPhoneNumber("other-phone"));
        assertThat(SamlUaaAuthenticationUserManager.haveUserAttributesChanged(existing, modified)).as("Phone number modified").isTrue();
    }

    @Test
    void haveAttributesChangedReturnsTrueForChangedVerified() {
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing).withVerified(!existing.isVerified()));
        assertThat(SamlUaaAuthenticationUserManager.haveUserAttributesChanged(existing, modified)).as("Verifiedemail modified").isTrue();
    }

    @Test
    void haveAttributesChangedReturnsTrueForChangedGivenName() {
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing).withGivenName("other-given"));
        assertThat(SamlUaaAuthenticationUserManager.haveUserAttributesChanged(existing, modified)).as("First name modified").isTrue();
    }

    @Test
    void haveAttributesChangedReturnsTrueForChangedFamilyName() {
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing).withFamilyName("other-family"));
        assertThat(SamlUaaAuthenticationUserManager.haveUserAttributesChanged(existing, modified)).as("Last name modified").isTrue();
    }

    @Test
    void getUserByDefaultUsesTheAvailableData() {
        SamlUaaAuthenticationUserManager userManager = new SamlUaaAuthenticationUserManager(null, null,null, null, null);

        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                "user",
                "user@example.com",
                OriginKeys.SAML,
                "user",
                ZONE_ID
        );
        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        attributes.add(EMAIL_ATTRIBUTE_NAME, "user@example.com");
        attributes.add(PHONE_NUMBER_ATTRIBUTE_NAME, "(415) 555-0111");
        attributes.add(GIVEN_NAME_ATTRIBUTE_NAME, "Jane");
        attributes.add(FAMILY_NAME_ATTRIBUTE_NAME, "Doe");
        attributes.add(EMAIL_VERIFIED_ATTRIBUTE_NAME, "true");

        UaaUser user = userManager.getUser(principal, attributes);
        assertThat(user)
                .returns("user", UaaUser::getUsername)
                .returns("user@example.com", UaaUser::getEmail)
                .returns("(415) 555-0111", UaaUser::getPhoneNumber)
                .returns("Jane", UaaUser::getGivenName)
                .returns("Doe", UaaUser::getFamilyName)
                .returns("", UaaUser::getPassword)
                .returns(true, UaaUser::isVerified)
                .returns(OriginKeys.SAML, UaaUser::getOrigin)
                .returns("user", UaaUser::getExternalId)
                .returns(ZONE_ID, UaaUser::getZoneId)
                .returns(0, u -> u.getAuthorities().size());
    }

    @Test
    void getUserWithoutVerifiedDefaultsToFalse() {
        SamlUaaAuthenticationUserManager userManager = new SamlUaaAuthenticationUserManager(null, null, null, null, null);

        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                "user",
                "user@example.com",
                null,
                "user",
                ZONE_ID
        );

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        UaaUser user = userManager.getUser(principal, attributes);
        assertThat(user).returns(false, UaaUser::isVerified);
    }

    @Test
    void throwsIfPrincipalUserNameAndUserAttributesEmailIsMissing() {
        SamlUaaAuthenticationUserManager userManager = new SamlUaaAuthenticationUserManager(null, null, null, null, null);

        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                null,
                "getUser Should look at the userAttributes email, not this one!",
                null,
                "user",
                ZONE_ID
        );

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();

        assertThatThrownBy(() -> userManager.getUser(principal, attributes))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Cannot determine username from credentials supplied");
    }
}
