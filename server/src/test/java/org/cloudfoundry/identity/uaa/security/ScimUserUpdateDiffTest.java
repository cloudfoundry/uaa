package org.cloudfoundry.identity.uaa.security;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScimUserUpdateDiffTest {
    private ScimUserUpdateDiff scimUserUpdateDiff;
    private MockHttpServletRequest httpRequest;
    private ScimUserProvisioning mockScimUserProvisioning;
    private ScimUser scimUserFromRequest;
    private ScimUser scimUserFromDB;
    private IdentityZone identityZone;
    private String scimUserID;

    private ScimUser makeUser() {
        ScimUser user = new ScimUser();
        ScimUser.Name scimUserName = new ScimUser.Name("originalGivenName", "originalFamilyName");
        user.setUserName("originalUserName");
        user.setPrimaryEmail("originalEmail@uaa.com");
        user.setName(scimUserName);
        user.setVerified(false);
        user.setActive(false);
        user.setOrigin(OriginKeys.UAA);
        user.setSalt("salt");
        user.setExternalId("external id");
        user.setNickName("nickname");
        user.setDisplayName("display name");
        user.addPhoneNumber("phone number");
        return user;
    }

    private void assertUpdateIsNotAllowed() {
        assertThat(scimUserUpdateDiff.isAnythingOtherThanNameDifferent(scimUserID, scimUserFromRequest)).isFalse();
    }

    private void assertUpdateIsAllowed() {
        assertThat(scimUserUpdateDiff.isAnythingOtherThanNameDifferent(scimUserID, scimUserFromRequest)).isTrue();
    }

    private void setRequestContent() {
        httpRequest.setContent(JsonUtils.writeValueAsBytes(scimUserFromRequest));
    }

    @BeforeEach
    void setUp() {
        httpRequest = new MockHttpServletRequest();

        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        scimUserUpdateDiff = new ScimUserUpdateDiff(mockScimUserProvisioning);

        scimUserID = RandomStringUtils.randomAlphabetic(5);

        scimUserFromRequest = makeUser();
        scimUserFromDB = makeUser();
        scimUserFromDB.setId(scimUserID);

        setRequestContent();

        identityZone = MultitenancyFixture.identityZone(RandomStringUtils.randomAlphabetic(5), RandomStringUtils.randomAlphabetic(5));
        IdentityZoneHolder.set(identityZone);

        when(mockScimUserProvisioning.retrieve(scimUserID, identityZone.getId())).thenReturn(scimUserFromDB);
        httpRequest.setPathInfo("/Users/" + scimUserID);
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
            void shouldNotBeAllowed() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenDisplayNameIsNull {
            @BeforeEach
            void nullSomeFieldsOfUserInDb() {
                scimUserFromDB.setDisplayName(null);
            }

            @Test
            void shouldNotBeAllowed() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenExternalIdIsNull {
            @BeforeEach
            void nullSomeFieldsOfUserInDb() {
                scimUserFromDB.setExternalId(null);
            }

            @Test
            void shouldNotBeAllowed() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenPhoneNumberIsNull {
            @BeforeEach
            void nullSomeFieldsOfUserInDb() {
                scimUserFromDB.setPhoneNumbers(null);
            }

            @Test
            void shouldNotBeAllowed() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenPhoneNumberIsAnEmptyList {
            @BeforeEach
            void nullSomeFieldsOfUserInDb() {
                scimUserFromDB.setPhoneNumbers(Lists.newArrayList());
            }

            @Test
            void shouldNotBeAllowed() {
                assertUpdateIsNotAllowed();
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
        void isAllowedToUpdate() {
            assertUpdateIsAllowed();
        }
    }

    @Nested
    class WhenChangingAnAllowedField {
        @Nested
        class WhenChangingName {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setName(new ScimUser.Name("updatedGivenName", "updatedFamilyName"));
                setRequestContent();
            }

            @Test
            void isAllowedToUpdate() {
                assertUpdateIsAllowed();
            }

            @Nested
            class WhenUserIsExternal {
                @BeforeEach
                void setup() {
                    scimUserFromDB.setOrigin("external");
                    scimUserFromRequest.setOrigin("external");
                }

                @Test
                void isNotAllowedToUpdate() {
                    assertUpdateIsNotAllowed();
                }
            }
        }

        @Nested
        class WhenNameIsNull {
            @BeforeEach
            void nullSomeFieldsOfUserInDb() {
                scimUserFromDB.setName(null);
            }

            @Test
            void shouldBeAllowed() {
                assertUpdateIsAllowed();
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
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheEmailField {
            @BeforeEach
            void setup() {
                ScimUser.Email email = new ScimUser.Email();
                email.setValue("another email");
                scimUserFromRequest.setEmails(Lists.newArrayList(email));
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheEmailFieldToAddASecondEmail {
            @BeforeEach
            void setup() {
                scimUserFromRequest.addEmail("abc");
                setRequestContent();
            }

            @Test
            void isAllowedToUpdateField() {
                assertUpdateIsAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheUsernameField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setUserName(null);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingThePhoneNumbersField {
            @BeforeEach
            void setup() {
                ScimUser.PhoneNumber phoneNumber = new ScimUser.PhoneNumber();
                phoneNumber.setValue("another phone number");
                scimUserFromRequest.setPhoneNumbers(Lists.newArrayList(phoneNumber));
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingThePhoneNumbersFieldToBecomeNull {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setPhoneNumbers(null);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingThePhoneNumbersListToBecomeEmpty {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setPhoneNumbers(Lists.newArrayList());
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheDisplayNameField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setDisplayName(null);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheExternalIdField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setExternalId(null);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheSaltField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setSalt(null);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheVerifiedField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setVerified(true);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheActiveField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setActive(true);
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }

        @Nested
        class WhenUpdatingTheOriginField {
            @BeforeEach
            void setup() {
                scimUserFromRequest.setOrigin("updatedOrigin");
                setRequestContent();
            }

            @Test
            void isNotAllowedToUpdateField() {
                assertUpdateIsNotAllowed();
            }
        }
    }

    @Nested
    class WhenNothingHasReallyChanged {
        @Nested
        class WhenSettingTheFieldsToBeTheSameAsItAlreadyWas {
            @BeforeEach
            void setup() {
                setRequestContent();
            }

            @Test
            void isAllowedToUpdateFieldBecauseItIsNotReallyAnUpdate() {
                assertUpdateIsAllowed();
            }
        }

        @Nested
        class WhenSettingTheOriginToAStringWhichHasNoContent {
            @Nested
            class WhenTheOriginStoredInTheDbWasUaa {
                @BeforeEach
                void setup() {
                    scimUserFromDB.setOrigin(OriginKeys.UAA);
                }

                @Nested
                class WhenTheNewOriginIsEmptyString {
                    @BeforeEach
                    void setup() {
                        scimUserFromRequest.setOrigin("");
                        setRequestContent();
                    }

                    @Test
                    void isAllowedToUpdateField_BecauseAnEmptyOriginIsStoredAsTheUaaOrigin() {
                        assertUpdateIsAllowed();
                    }
                }

                @Nested
                class WhenTheNewOriginIsNull {
                    @BeforeEach
                    void setup() {
                        scimUserFromRequest.setOrigin(null);
                        setRequestContent();
                    }

                    @Test
                    void isAllowedToUpdateField_BecauseAnEmptyOriginIsStoredAsTheUaaOrigin() {
                        assertUpdateIsAllowed();
                    }
                }
            }

            @Nested
            class WhenTheOriginStoredInTheDbWasAnythingOtherThanUaa {
                @BeforeEach
                void setup() {
                    scimUserFromDB.setOrigin("not" + OriginKeys.UAA);
                    scimUserFromRequest.setOrigin("");
                    setRequestContent();
                }

                @Test
                void isNotAllowedToUpdateField_BecauseAnEmptyOriginIsTreatedAsTheUaaOriginWhichIsNotTheSameAsWhatWasAlreadyStored() {
                    assertUpdateIsNotAllowed();
                }
            }
        }

        @Nested
        class WhenThereAreAdditionalPhoneNumbersButTheFirstPhoneNumberIsTheSame {
            @BeforeEach
            void setup() {
                scimUserFromRequest.addPhoneNumber("second phone number");
                scimUserFromRequest.addPhoneNumber("third phone number");
                setRequestContent();
            }

            @Test
            void isAllowedToUpdateField_BecauseTheFirstPhoneNumberDidNotChangeAndOnlyTheFirstPhoneNumberActuallyGetsStored() {
                assertUpdateIsAllowed();
            }
        }

        @Nested
        class WhenThereAreAdditionalEmailsButThePrimaryEmailIsTheSame {
            @BeforeEach
            void setup() {
                scimUserFromRequest.addEmail("second email");
                scimUserFromRequest.addEmail("third email");
                setRequestContent();
            }

            @Test
            void isAllowedToUpdateField_BecauseThePrimaryEmailDidNotChangeAndOnlyThePrimaryEmailActuallyGetsStored() {
                assertUpdateIsAllowed();
            }
        }
    }
}
