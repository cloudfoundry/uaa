package org.cloudfoundry.identity.uaa.events;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEvent;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class UserAttributeChangedEventTest {

    private static final String USER_ID = "test-user-id";
    private static final String USERNAME = "testuser@example.com";
    private static final String EMAIL = "test@example.com";
    private static final String GIVEN_NAME = "John";
    private static final String FAMILY_NAME = "Doe";
    private static final String PHONE_NUMBER = "+1234567890";
    private static final String ZONE_ID = "uaa";

    private Object eventSource;
    private UaaUser existingUser;
    private UaaUser updatedUser;

    @BeforeEach
    void setUp() {
        eventSource = new Object();
        existingUser = createTestUser(USER_ID, USERNAME, EMAIL, GIVEN_NAME, FAMILY_NAME, PHONE_NUMBER, new Date());
        updatedUser = createTestUser(USER_ID, USERNAME, "updated@example.com", GIVEN_NAME, FAMILY_NAME, PHONE_NUMBER, new Date());
    }

    @Test
    void constructor_shouldCreateEvent_withValidParameters() {
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, updatedUser);

        // Then
        assertNotNull(event);
        assertEquals(eventSource, event.getSource());
        assertEquals(existingUser, event.getExistingUser());
        assertEquals(updatedUser, event.getUpdatedUser());
    }

    @Test
    void constructor_shouldCreateEvent_withNullExistingUser() {
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, null, updatedUser);

        // Then
        assertNotNull(event);
        assertEquals(eventSource, event.getSource());
        assertNull(event.getExistingUser());
        assertEquals(updatedUser, event.getUpdatedUser());
    }

    @Test
    void constructor_shouldCreateEvent_withNullUpdatedUser() {
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, null);

        // Then
        assertNotNull(event);
        assertEquals(eventSource, event.getSource());
        assertEquals(existingUser, event.getExistingUser());
        assertNull(event.getUpdatedUser());
    }

    @Test
    void constructor_shouldCreateEvent_withBothUsersNull() {
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, null, null);

        // Then
        assertNotNull(event);
        assertEquals(eventSource, event.getSource());
        assertNull(event.getExistingUser());
        assertNull(event.getUpdatedUser());
    }

    @Test
    void constructor_shouldThrowException_withNullSource() {
        // When & Then
        assertThrows(IllegalArgumentException.class, () -> {
            new UserAttributeChangedEvent(null, existingUser, updatedUser);
        }, "Constructor should throw exception when source is null");
    }

    @Test
    void getExistingUser_shouldReturnCorrectUser() {
        // Given
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, updatedUser);

        // When
        UaaUser result = event.getExistingUser();

        // Then
        assertEquals(existingUser, result);
        assertEquals(USER_ID, result.getId());
        assertEquals(USERNAME, result.getUsername());
        assertEquals(EMAIL, result.getEmail());
    }

    @Test
    void getUpdatedUser_shouldReturnCorrectUser() {
        // Given
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, updatedUser);

        // When
        UaaUser result = event.getUpdatedUser();

        // Then
        assertEquals(updatedUser, result);
        assertEquals(USER_ID, result.getId());
        assertEquals(USERNAME, result.getUsername());
        assertEquals("updated@example.com", result.getEmail());
    }

    @Test
    void toString_shouldReturnFormattedString_withValidUpdatedUser() {
        // Given
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, updatedUser);

        // When
        String result = event.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("UserAttributeChangedEvent"));
        assertTrue(result.contains("userId=" + USER_ID));
        assertTrue(result.contains("{"));
        assertTrue(result.contains("}"));
    }

    @Test
    void toString_shouldReturnFormattedString_withNullUpdatedUser() {
        // Given
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, null);

        // When
        String result = event.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("UserAttributeChangedEvent"));
        assertTrue(result.contains("userId=null"));
        assertTrue(result.contains("{"));
        assertTrue(result.contains("}"));
    }

    @Test
    void event_shouldInheritFromApplicationEvent() {
        // Given
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, updatedUser);

        // When & Then
        assertTrue(event instanceof ApplicationEvent, "Event should inherit from ApplicationEvent");
    }

    @Test
    void event_shouldHaveCorrectTimestamp() {
        // Given
        long beforeEventCreation = System.currentTimeMillis();
        
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, updatedUser);
        
        // Then
        long afterEventCreation = System.currentTimeMillis();
        assertTrue(event.getTimestamp() >= beforeEventCreation, "Event timestamp should be after creation start");
        assertTrue(event.getTimestamp() <= afterEventCreation, "Event timestamp should be before creation end");
    }

    @Test
    void event_shouldMaintainSourceReference() {
        // Given
        String specificSource = "TestEventPublisher";
        
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(specificSource, existingUser, updatedUser);

        // Then
        assertEquals(specificSource, event.getSource());
    }

    @Test
    void event_shouldHandleDifferentUserTypes() {
        // Given
        UaaUser user1 = createTestUser("id1", "user1", "email1@test.com", "First1", "Last1", "+1111111111", new Date());
        UaaUser user2 = createTestUser("id2", "user2", "email2@test.com", "First2", "Last2", "+2222222222", new Date());

        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, user1, user2);

        // Then
        assertEquals(user1, event.getExistingUser());
        assertEquals(user2, event.getUpdatedUser());
        assertNotEquals(event.getExistingUser().getId(), event.getUpdatedUser().getId());
        assertNotEquals(event.getExistingUser().getUsername(), event.getUpdatedUser().getUsername());
    }

    @Test
    void event_shouldHandleUsersWithSameId() {
        // Given
        UaaUser originalUser = createTestUser(USER_ID, USERNAME, EMAIL, GIVEN_NAME, FAMILY_NAME, PHONE_NUMBER, new Date());
        UaaUser modifiedUser = createTestUser(USER_ID, USERNAME, "different@email.com", GIVEN_NAME, FAMILY_NAME, PHONE_NUMBER, new Date());

        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, originalUser, modifiedUser);

        // Then
        assertEquals(originalUser, event.getExistingUser());
        assertEquals(modifiedUser, event.getUpdatedUser());
        assertEquals(event.getExistingUser().getId(), event.getUpdatedUser().getId());
        assertEquals(event.getExistingUser().getUsername(), event.getUpdatedUser().getUsername());
        assertNotEquals(event.getExistingUser().getEmail(), event.getUpdatedUser().getEmail());
    }

    @Test
    void event_shouldBeImmutableAfterCreation() {
        // Given
        UaaUser originalExisting = createTestUser(USER_ID, USERNAME, EMAIL, GIVEN_NAME, FAMILY_NAME, PHONE_NUMBER, new Date());
        UaaUser originalUpdated = createTestUser(USER_ID, USERNAME, "updated@email.com", GIVEN_NAME, FAMILY_NAME, PHONE_NUMBER, new Date());
        
        // When
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, originalExisting, originalUpdated);

        // Then
        assertEquals(originalExisting, event.getExistingUser());
        assertEquals(originalUpdated, event.getUpdatedUser());
        
        // The event should maintain references to the original users
        assertSame(originalExisting, event.getExistingUser());
        assertSame(originalUpdated, event.getUpdatedUser());
    }

    @Test
    void toString_shouldHandleComplexUserData() {
        // Given
        UaaUser complexUser = createTestUser(
            "complex-id-with-special-chars-123!@#",
            "complex.user+test@example-domain.co.uk",
            "complex.email+tag@long-domain-name.example.org",
            "Very Long Given Name",
            "Hyphenated-Family-Name",
            "+1-555-123-4567",
            new Date()
        );
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(eventSource, existingUser, complexUser);

        // When
        String result = event.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("UserAttributeChangedEvent"));
        assertTrue(result.contains("userId=complex-id-with-special-chars-123!@#"));
        // Should not throw exceptions with special characters
        assertDoesNotThrow(() -> event.toString());
    }

    // Helper method to create test users
    private UaaUser createTestUser(String id, String username, String email, String givenName, String familyName, String phoneNumber, Date lastLogonTime) {
        return new UaaUser(
            new UaaUserPrototype()
                .withId(id)
                .withUsername(username)
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withZoneId(ZONE_ID)
                .withLastLogonSuccess(lastLogonTime != null ? lastLogonTime.getTime() : null)
        );
    }
}
