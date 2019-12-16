package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserInfoResponseJsonTests {

    @Test
    void deserializeTest() {
        String json = getResourceAsString(this.getClass(), "UserInfoResponseJsonTests.json");

        assertHardcodedValues(json);
    }

    @Test
    void serializeTest() {
        String json = getResourceAsString(this.getClass(), "UserInfoResponseJsonTests.json");

        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        json = JsonUtils.writeValueAsString(response);
        assertHardcodedValues(json);
    }

    private static void assertHardcodedValues(String json) {
        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        assertEquals("olds@vmware.com", response.getEmail());
        assertEquals("Dale", response.getGivenName());
        assertEquals("Olds", response.getFamilyName());
        assertEquals("Dale Olds", response.getFullName());
        assertEquals("8505551234", response.getPhoneNumber());
        assertEquals("12345", response.getUserId());
        assertEquals("12345", response.getSub());
        assertEquals("olds", response.getUserName());
        assertTrue(response.isEmailVerified());

        assertThat(
                response.getUserAttributes().get("Key 1"),
                hasItems(CoreMatchers.is("Val 11"), CoreMatchers.is("Val 12"))
        );
        assertThat(
                response.getUserAttributes().get("Key 2"),
                hasItems(CoreMatchers.is("Val 21"), CoreMatchers.is("Val 22"))
        );

        assertThat(
                response.getRoles(),
                hasItems(
                        CoreMatchers.is("role12"),
                        CoreMatchers.is("role54"),
                        CoreMatchers.is("role134"),
                        CoreMatchers.is("role812")
                )
        );
        assertEquals(Long.valueOf(1000L), response.previousLogonSuccess);
    }
}
