package org.cloudfoundry.identity.uaa.security;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScimUserSelfUpdateAllowedTest {
    private ScimUserSelfUpdateAllowed scimUserSelfUpdateAllowed;
    private MockHttpServletRequest httpRequest;
    private ScimUserProvisioning mockScimUserProvisioning;
    private ScimUser scimUserFromRequest;
    private ScimUser scimUserFromDB;
    private IdentityZone identityZone;
    private String scimUserID;

    @BeforeEach
    void setUp() {
        httpRequest = new MockHttpServletRequest();

        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        scimUserSelfUpdateAllowed = new ScimUserSelfUpdateAllowed(mockScimUserProvisioning);

        scimUserFromRequest = new ScimUser();
        scimUserID = RandomStringUtils.randomAlphabetic(5);
        scimUserFromRequest.setUserName("originalUserName");
        scimUserFromRequest.setPrimaryEmail("originalEmail@uaa.com");
        ScimUser.Name scimUserName = new ScimUser.Name("originalGivenName", "originalFamilyName");
        scimUserFromRequest.setName(scimUserName);
        scimUserFromRequest.setVerified(false);
        scimUserFromRequest.setActive(false);
        scimUserFromRequest.setOrigin("originalOrigin");
        scimUserFromRequest.setSalt("salt");
        scimUserFromRequest.setExternalId("external id");
        scimUserFromRequest.setNickName("nickname");
        scimUserFromRequest.setDisplayName("display name");
        scimUserFromRequest.addPhoneNumber("phone number");
        httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));

        scimUserFromDB = new ScimUser();
        scimUserFromDB.setId(scimUserID);
        scimUserFromDB.setUserName("originalUserName");
        scimUserFromDB.setPrimaryEmail("originalEmail@uaa.com");
        ScimUser.Name scimUserNameFromDB = new ScimUser.Name("originalGivenName", "originalFamilyName");
        scimUserFromDB.setName(scimUserNameFromDB);
        scimUserFromDB.setVerified(false);
        scimUserFromDB.setActive(false);
        scimUserFromDB.setSalt("salt");
        scimUserFromDB.setOrigin("originalOrigin");
        scimUserFromDB.setExternalId("external id");
        scimUserFromDB.setNickName("nickname");
        scimUserFromDB.setDisplayName("display name");
        scimUserFromDB.addPhoneNumber("phone number");

        identityZone = MultitenancyFixture.identityZone(RandomStringUtils.randomAlphabetic(5), RandomStringUtils.randomAlphabetic(5));
        IdentityZoneHolder.set(identityZone);

        when(mockScimUserProvisioning.retrieve(scimUserID, identityZone.getId())).thenReturn(scimUserFromDB);
        httpRequest.setPathInfo("/Users/" + scimUserID);
    }

    @Nested
    class WithInternalUserStoreEnabled {
        private boolean disableInternalUserManagement;

        @BeforeEach
        void enableInternalUserManagement() {
            disableInternalUserManagement = false;
        }

        @Nested
        class WhenSomeFieldsOnTheUserAreNullInTheDb {
            @Nested
            class WhenSaltIsNull {
                @BeforeEach
                void nullSomeFieldsOfUserInDb() {
                    scimUserFromDB.setSalt(null);
                }

                @Test
                void shouldNotBeAllowed() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenDisplayNameIsNull {
                @BeforeEach
                void nullSomeFieldsOfUserInDb() {
                    scimUserFromDB.setDisplayName(null);
                }

                @Test
                void shouldNotBeAllowed() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenExternalIdIsNull {
                @BeforeEach
                void nullSomeFieldsOfUserInDb() {
                    scimUserFromDB.setExternalId(null);
                }

                @Test
                void shouldNotBeAllowed() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenPhoneNumberIsNull {
                @BeforeEach
                void nullSomeFieldsOfUserInDb() {
                    scimUserFromDB.setPhoneNumbers(null);
                }

                @Test
                void shouldNotBeAllowed() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }
        }

        @Nested
        class WhenScimUserDoesNotExist {
            @BeforeEach
            void setupNoUserInDB() {
                when(mockScimUserProvisioning.retrieve(scimUserID, identityZone.getId())).thenThrow(ScimResourceNotFoundException.class);
            }

            @Test
            void isAllowedToUpdate() throws IOException {
                assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(true));
            }
        }

        @Nested
        class WhenChangingAnAllowedField {
            @Nested
            class WhenChangingName {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setName(new ScimUser.Name("updatedGivenName", "updatedFamilyName"));
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isAllowedToUpdate() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(true));
                }
            }

            @Nested
            class WhenNameIsNull {
                @BeforeEach
                void nullSomeFieldsOfUserInDb() {
                    scimUserFromDB.setName(null);
                }

                @Test
                void shouldBeAllowed() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(true));
                }
            }
        }

        @Nested
        class WhenAttemptingToUpdateAFieldThatIsNotAllowedToBeUpdated {
            @Nested
            class WhenUpdatingThePrimaryEmailField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setEmails(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheEmailField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.addEmail("abc");
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheUsernameField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setUserName(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingThePhoneNumbersField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.addPhoneNumber("another phone number");
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheDisplayNameField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setDisplayName(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheExternalIdField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setExternalId(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheSaltField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setSalt(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheVerifiedField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setVerified(true);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheActiveField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setActive(true);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }
        }

    }

    @Nested
    class WithInternalUserStoreDisabled {
        private boolean disableInternalUserManagement;

        @BeforeEach
        void disableInternalUserManagement() {
            disableInternalUserManagement = true;
        }

        @Nested
        class WhenScimUserDoesNotExist {
            @BeforeEach
            void setupNoUserInDB() {
                when(mockScimUserProvisioning.retrieve(scimUserID, identityZone.getId())).thenThrow(ScimResourceNotFoundException.class);
            }

            @Test
            void isAllowedToUpdate() throws IOException {
                assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(true));
            }
        }

        @Nested
        class WhenAttemptingToUpdateAFieldThatIsNotAllowedToBeUpdated {

            @Nested
            class WhenUpdatingThePrimaryEmailField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setEmails(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheEmailField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.addEmail("abc");
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheUsernameField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setUserName(null);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheVerifiedField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setVerified(true);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheActiveField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setActive(true);
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenUpdatingTheOriginField {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setOrigin("updatedOrigin");
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isNotAllowedToUpdateField() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }

            @Nested
            class WhenChangingName {
                @BeforeEach
                void setup() {
                    scimUserFromRequest.setName(new ScimUser.Name("updatedGivenName", "updatedFamilyName"));
                    httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
                }

                @Test
                void isAllowedToUpdate() throws IOException {
                    assertThat(scimUserSelfUpdateAllowed.isAllowed(scimUserID, scimUserFromRequest, disableInternalUserManagement), is(false));
                }
            }
        }
    }
}