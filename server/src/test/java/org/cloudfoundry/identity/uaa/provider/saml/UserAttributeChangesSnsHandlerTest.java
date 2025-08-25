package org.cloudfoundry.identity.uaa.provider.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ge.iam.sns.service.MessageBuilder;
import com.ge.iam.sns.service.SnsService;
import org.cloudfoundry.identity.uaa.events.UserAttributeChangedEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserAttributeChangesSnsHandlerTest {

    @Mock
    private SnsService mockSnsService;

    private UserAttributeChangesSnsHandler snsHandler;
    private ObjectMapper objectMapper;

    private static final String VALID_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:user-events";
    private static final String DEFAULT_ZONE_ID = "uaa";
    private static final String USER_ID = "test-user-id";
    private static final String USERNAME = "testuser@example.com";
    private static final String ORIGINAL_EMAIL = "original@example.com";
    private static final String UPDATED_EMAIL = "updated@example.com";
    private static final String ORIGINAL_GIVEN_NAME = "John";
    private static final String UPDATED_GIVEN_NAME = "Jonathan";
    private static final String ORIGINAL_FAMILY_NAME = "Doe";
    private static final String UPDATED_FAMILY_NAME = "Smith";
    private static final String ORIGINAL_PHONE = "+1234567890";
    private static final String UPDATED_PHONE = "+1987654321";

    @BeforeEach
    void setUp() {
        snsHandler = new UserAttributeChangesSnsHandler(mockSnsService);
        objectMapper = new ObjectMapper();
        
     
        ReflectionTestUtils.setField(snsHandler, "snsTopicArn", VALID_TOPIC_ARN);
        ReflectionTestUtils.setField(snsHandler, "snsEnabled", true);
    }

    @Test
    void constructor_shouldInitializeCorrectly() {
        UserAttributeChangesSnsHandler handler = new UserAttributeChangesSnsHandler(mockSnsService);

        assertNotNull(handler);
        assertEquals(mockSnsService, ReflectionTestUtils.getField(handler, "snsService"));
    }

    @Test
    void isConfiguredAndEnabled_shouldReturnTrue_whenProperlyConfigured() {
    
        ReflectionTestUtils.setField(snsHandler, "snsEnabled", true);
        ReflectionTestUtils.setField(snsHandler, "snsTopicArn", VALID_TOPIC_ARN);

        boolean result = snsHandler.isConfiguredAndEnabled();
        assertTrue(result);
    }

    @Test
    void isConfiguredAndEnabled_shouldReturnFalse_whenSnsDisabled() {

        ReflectionTestUtils.setField(snsHandler, "snsEnabled", false);
        ReflectionTestUtils.setField(snsHandler, "snsTopicArn", VALID_TOPIC_ARN);

        boolean result = snsHandler.isConfiguredAndEnabled();

        assertFalse(result);
    }

    @Test
    void isConfiguredAndEnabled_shouldReturnFalse_whenTopicArnBlank() {
  
        ReflectionTestUtils.setField(snsHandler, "snsEnabled", true);
        ReflectionTestUtils.setField(snsHandler, "snsTopicArn", "");

    
        boolean result = snsHandler.isConfiguredAndEnabled();

       
        assertFalse(result);
    }

    @Test
    void isConfiguredAndEnabled_shouldReturnFalse_whenTopicArnIsDefaultValue() {
       
        ReflectionTestUtils.setField(snsHandler, "snsEnabled", true);
        ReflectionTestUtils.setField(snsHandler, "snsTopicArn", "arn");

        
        boolean result = snsHandler.isConfiguredAndEnabled();

       
        assertFalse(result);
    }

    @Test
    void handleUserAttributeChanged_shouldSkip_whenSnsDisabled() {
       
        ReflectionTestUtils.setField(snsHandler, "snsEnabled", false);
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verifyNoInteractions(mockSnsService);
    }

    @Test
    void handleUserAttributeChanged_shouldSkip_whenExistingUserIsNull() {
       
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, null, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verifyNoInteractions(mockSnsService);
    }

    @Test
    void handleUserAttributeChanged_shouldSkip_whenUpdatedUserIsNull() {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, null);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verifyNoInteractions(mockSnsService);
    }

    @Test
    void handleUserAttributeChanged_shouldSkip_whenTopicArnNotConfigured() {
       
        ReflectionTestUtils.setField(snsHandler, "snsTopicArn", "arn");
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verifyNoInteractions(mockSnsService);
    }

    @Test
    void handleUserAttributeChanged_shouldSkip_whenNoChangesDetected() {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verifyNoInteractions(mockSnsService);
    }

    @Test
    void handleUserAttributeChanged_shouldPublishMessage_whenEmailChanged() throws Exception {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> subjectCaptor = ArgumentCaptor.forClass(String.class);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verify(mockSnsService).publishAsync(topicCaptor.capture(), subjectCaptor.capture(), any(MessageBuilder.class));
        
        assertEquals(VALID_TOPIC_ARN, topicCaptor.getValue());
        assertEquals("UAA User Event", subjectCaptor.getValue());
    }

    @Test
    void handleUserAttributeChanged_shouldPublishMessage_whenMultipleFieldsChanged() throws Exception {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, UPDATED_GIVEN_NAME, UPDATED_FAMILY_NAME, UPDATED_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void handleUserAttributeChanged_shouldPublishMessage_whenOnlyLastLogonTimeChanged() throws Exception {
       
        Date originalDate = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago
        Date updatedDate = new Date();
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, originalDate);
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, updatedDate);
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void handleUserAttributeChanged_shouldPublishMessage_forFirstTimeLogin() throws Exception {
        // First time login (existing user has null lastLogonTime)
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, null);
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        // When
        snsHandler.handleUserAttributeChanged(event);

        // Then
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void handleUserAttributeChanged_shouldIgnoreNameSwap() {
        // Names are swapped (common data quality issue)
        Date sameDate = new Date(); // Use same date instance to avoid lastLogonTime being detected as changed
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, "John", "Doe", ORIGINAL_PHONE, sameDate);
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, "Doe", "John", ORIGINAL_PHONE, sameDate);
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        // When
        snsHandler.handleUserAttributeChanged(event);

        // Then
        verifyNoInteractions(mockSnsService);
    }

    @Test
    void handleUserAttributeChanged_shouldHandleUsernameChange() throws Exception {
       
        UaaUser existingUser = createTestUser(USER_ID, "old-username", ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, "new-username", ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        
        snsHandler.handleUserAttributeChanged(event);

       
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void handleUserAttributeChanged_shouldHandleNullValues() throws Exception {
        // User with some null values (but email is required, so we provide it)
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, null, null, null, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, UPDATED_GIVEN_NAME, UPDATED_FAMILY_NAME, UPDATED_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        // When
        snsHandler.handleUserAttributeChanged(event);

        // Then
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void handleUserAttributeChanged_shouldHandleExceptionGracefully() {
        // Given
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        doThrow(new RuntimeException("SNS service unavailable")).when(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));

        // When & Then - Should not throw exception
        assertDoesNotThrow(() -> snsHandler.handleUserAttributeChanged(event));
        
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void handleUserAttributeChanged_shouldCallPublishAsyncForValidChanges() {
        // Given - Test that publishAsync is called when there are valid changes
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UserAttributeChangedEvent event = new UserAttributeChangedEvent(this, existingUser, updatedUser);

        // When
        assertDoesNotThrow(() -> snsHandler.handleUserAttributeChanged(event));
        
        // Then - publishAsync should be called with correct parameters
        verify(mockSnsService).publishAsync(anyString(), anyString(), any(MessageBuilder.class));
    }

    @Test
    void getChangedFields_shouldDetectEmailChange() {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, UPDATED_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());

        
        Map<String, Object> changedFields = invokeGetChangedFields(existingUser, updatedUser);

       
        assertEquals(1, changedFields.size());
        assertEquals(UPDATED_EMAIL, changedFields.get("email"));
    }

    @Test
    void getChangedFields_shouldDetectGivenNameChange() {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, UPDATED_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());

        
        Map<String, Object> changedFields = invokeGetChangedFields(existingUser, updatedUser);

       
        assertEquals(1, changedFields.size());
        assertEquals(UPDATED_GIVEN_NAME, changedFields.get("givenName"));
    }

    @Test
    void getChangedFields_shouldDetectFamilyNameChange() {
       
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, UPDATED_FAMILY_NAME, ORIGINAL_PHONE, new Date());

        
        Map<String, Object> changedFields = invokeGetChangedFields(existingUser, updatedUser);

       
        assertEquals(1, changedFields.size());
        assertEquals(UPDATED_FAMILY_NAME, changedFields.get("familyName"));
    }

    @Test
    void getChangedFields_shouldDetectPhoneNumberChange() {
       
        Date sameDate = new Date(); 
        UaaUser existingUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, sameDate);
        UaaUser updatedUser = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, UPDATED_PHONE, sameDate);

        
        Map<String, Object> changedFields = invokeGetChangedFields(existingUser, updatedUser);

       
        assertEquals(1, changedFields.size());
        assertEquals(UPDATED_PHONE, changedFields.get("phoneNumber"));
    }

    @Test
    void createUserEventMessage_shouldCreateCorrectMessage() {
       
        UaaUser user = createTestUser(USER_ID, USERNAME, ORIGINAL_EMAIL, ORIGINAL_GIVEN_NAME, ORIGINAL_FAMILY_NAME, ORIGINAL_PHONE, new Date());
        Map<String, Object> changedFields = Map.of("email", UPDATED_EMAIL);

        
        Map<String, Object> message = invokeCreateUserEventMessage(user, changedFields);

       
        assertEquals("USER_DATA_UPDATED", message.get("eventType"));
        assertEquals("uaa-saml-provider", message.get("source"));
        assertEquals("1.0", message.get("version"));
        assertEquals(USERNAME, message.get("username"));
        assertEquals(DEFAULT_ZONE_ID, message.get("instanceZoneId"));
        assertEquals(changedFields, message.get("changedFields"));
    }

    @Test
    void determineEventType_shouldReturnLoginTimeUpdated_forLastLogonTimeOnly() {
       
        Map<String, Object> changedFields = Map.of("lastLogonTime", System.currentTimeMillis());

        
        String eventType = invokeDetermineEventType(changedFields);

       
        assertEquals("LOGIN_TIME_UPDATED", eventType);
    }

    @Test
    void determineEventType_shouldReturnUserDataUpdated_forOtherChanges() {
       
        Map<String, Object> changedFields = Map.of("email", UPDATED_EMAIL);

        
        String eventType = invokeDetermineEventType(changedFields);

       
        assertEquals("USER_DATA_UPDATED", eventType);
    }

    @Test
    void determineEventType_shouldReturnUserDataUpdated_forMultipleChanges() {
       
        Map<String, Object> changedFields = Map.of(
            "lastLogonTime", System.currentTimeMillis(),
            "email", UPDATED_EMAIL
        );

        
        String eventType = invokeDetermineEventType(changedFields);

       
        assertEquals("USER_DATA_UPDATED", eventType);
    }

    // Helper methods

    private UaaUser createTestUser(String id, String username, String email, String givenName, String familyName, String phoneNumber, Date lastLogonTime) {
        return new UaaUser(
            new UaaUserPrototype()
                .withId(id)
                .withUsername(username)
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withZoneId(DEFAULT_ZONE_ID)
                .withLastLogonSuccess(lastLogonTime != null ? lastLogonTime.getTime() : null)
        );
    }

    private Map<String, Object> invokeGetChangedFields(UaaUser existingUser, UaaUser updatedUser) {
        try {
            return (Map<String, Object>) ReflectionTestUtils.invokeMethod(snsHandler, "getChangedFields", existingUser, updatedUser);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Map<String, Object> invokeCreateUserEventMessage(UaaUser user, Map<String, Object> changedFields) {
        try {
            return (Map<String, Object>) ReflectionTestUtils.invokeMethod(snsHandler, "createUserEventMessage", user, changedFields);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String invokeDetermineEventType(Map<String, Object> changedFields) {
        try {
            return (String) ReflectionTestUtils.invokeMethod(snsHandler, "determineEventType", changedFields);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
