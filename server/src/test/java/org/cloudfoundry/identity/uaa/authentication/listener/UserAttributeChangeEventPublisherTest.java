package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.events.UserAttributeChangedEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserAttributeChangeEventPublisherTest {

    @Mock
    private ApplicationEventPublisher mockPublisher;

    private UserAttributeChangeEventPublisher publisher;
    private Object source;
    private UaaUser userBefore;
    private UaaUser userAfter;

    @BeforeEach
    void setUp() {
        publisher = new UserAttributeChangeEventPublisher(mockPublisher);
        source = new Object();
        
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withId("user-id")
                .withUsername("testuser")
                .withEmail("test@example.com")
                .withGivenName("Test")
                .withFamilyName("User");
        
        userBefore = new UaaUser(prototype);
        userAfter = new UaaUser(prototype.withLastLogonSuccess(System.currentTimeMillis()));
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_success() {
        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        ArgumentCaptor<UserAttributeChangedEvent> eventCaptor = ArgumentCaptor.forClass(UserAttributeChangedEvent.class);
        verify(mockPublisher, timeout(1000).times(1)).publishEvent(eventCaptor.capture());
        
        UserAttributeChangedEvent capturedEvent = eventCaptor.getValue();
        assertNotNull(capturedEvent);
        assertEquals(source, capturedEvent.getSource());
        assertNotNull(capturedEvent.getExistingUser());
        assertNotNull(capturedEvent.getUpdatedUser());
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withPreviousUser() {
        // Arrange - This test is now redundant since we don't use withPreviousUser anymore
        // But keeping it to verify behavior doesn't break
        UaaUser userWithPrevious = userAfter.withPreviousUser(userBefore);

        // Act - The publisher ignores the previousUser and uses the direct parameters
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userWithPrevious);

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - should use userBefore as existingUser (from parameter, not from previousUser)
        ArgumentCaptor<UserAttributeChangedEvent> eventCaptor = ArgumentCaptor.forClass(UserAttributeChangedEvent.class);
        verify(mockPublisher, timeout(1000).times(1)).publishEvent(eventCaptor.capture());
        
        UserAttributeChangedEvent capturedEvent = eventCaptor.getValue();
        assertNotNull(capturedEvent);
        assertEquals(userBefore, capturedEvent.getExistingUser());
        // Updated user is userWithPrevious (but withPreviousUser doesn't affect the comparison anymore)
        assertNotNull(capturedEvent.getUpdatedUser());
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withNullPreviousUser() {
        // Arrange - userAfter has no previous user set
        
        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        ArgumentCaptor<UserAttributeChangedEvent> eventCaptor = ArgumentCaptor.forClass(UserAttributeChangedEvent.class);
        verify(mockPublisher, timeout(1000).times(1)).publishEvent(eventCaptor.capture());
        
        UserAttributeChangedEvent capturedEvent = eventCaptor.getValue();
        assertNotNull(capturedEvent);
        assertEquals(userBefore, capturedEvent.getExistingUser());
        assertEquals(userAfter, capturedEvent.getUpdatedUser());
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withNullPublisher() {
        // Arrange
        UserAttributeChangeEventPublisher publisherWithNullPublisher = 
                new UserAttributeChangeEventPublisher(null);

        // Act - should not throw exception
        assertDoesNotThrow(() -> {
            publisherWithNullPublisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);
        });

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - no interaction with the null publisher
        verifyNoInteractions(mockPublisher);
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_handleException() {
        // Arrange
        doThrow(new RuntimeException("Test exception")).when(mockPublisher).publishEvent(any());

        // Act - should not throw exception, error should be logged
        assertDoesNotThrow(() -> {
            publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);
        });

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert - method was called despite exception
        verify(mockPublisher, timeout(1000).atLeastOnce()).publishEvent(any(UserAttributeChangedEvent.class));
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_withDifferentSource() {
        // Arrange
        String differentSource = "DifferentSource";

        // Act
        publisher.publishUserAttributeChangeEventAsync(differentSource, userBefore, userAfter);

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        ArgumentCaptor<UserAttributeChangedEvent> eventCaptor = ArgumentCaptor.forClass(UserAttributeChangedEvent.class);
        verify(mockPublisher, timeout(1000).times(1)).publishEvent(eventCaptor.capture());
        
        UserAttributeChangedEvent capturedEvent = eventCaptor.getValue();
        assertEquals(differentSource, capturedEvent.getSource());
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_multipleInvocations() {
        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);

        // Allow async execution to complete
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        verify(mockPublisher, timeout(1000).times(3)).publishEvent(any(UserAttributeChangedEvent.class));
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_verifyEventDetails() {
        // Arrange
        UaaUserPrototype beforePrototype = new UaaUserPrototype()
                .withId("user-123")
                .withUsername("john.doe")
                .withEmail("john@example.com")
                .withGivenName("John")
                .withFamilyName("Doe")
                .withLastLogonSuccess(1000L);
        
        UaaUserPrototype afterPrototype = new UaaUserPrototype()
                .withId("user-123")
                .withUsername("john.doe")
                .withEmail("john.new@example.com")
                .withGivenName("John")
                .withFamilyName("Doe")
                .withLastLogonSuccess(2000L);

        UaaUser before = new UaaUser(beforePrototype);
        UaaUser after = new UaaUser(afterPrototype);

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, before, after);

        // Allow async execution to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        ArgumentCaptor<UserAttributeChangedEvent> eventCaptor = ArgumentCaptor.forClass(UserAttributeChangedEvent.class);
        verify(mockPublisher, timeout(1000).times(1)).publishEvent(eventCaptor.capture());
        
        UserAttributeChangedEvent capturedEvent = eventCaptor.getValue();
        assertNotNull(capturedEvent.getExistingUser());
        assertNotNull(capturedEvent.getUpdatedUser());
        assertEquals("john.doe", capturedEvent.getExistingUser().getUsername());
        assertEquals("john.doe", capturedEvent.getUpdatedUser().getUsername());
        assertEquals("john@example.com", capturedEvent.getExistingUser().getEmail());
        assertEquals("john.new@example.com", capturedEvent.getUpdatedUser().getEmail());
    }

    @Test
    void testConstructor_withValidPublisher() {
        // Act
        UserAttributeChangeEventPublisher newPublisher = 
                new UserAttributeChangeEventPublisher(mockPublisher);

        // Assert
        assertNotNull(newPublisher);
    }

    @Test
    void testConstructor_withNullPublisher() {
        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> {
            new UserAttributeChangeEventPublisher(null);
        });
    }

    @Test
    void testPublishUserAttributeChangeEventAsync_asyncBehavior() {
        // This test verifies that the method is truly async
        // by checking that it returns immediately without blocking
        
        // Arrange
        long startTime = System.currentTimeMillis();

        // Act
        publisher.publishUserAttributeChangeEventAsync(source, userBefore, userAfter);

        // Assert - method should return quickly (within 50ms)
        long endTime = System.currentTimeMillis();
        assertTrue((endTime - startTime) < 50, 
                "Method should return quickly due to async execution");

        // Verify the event is published (might take longer due to async)
        verify(mockPublisher, timeout(1000).times(1)).publishEvent(any(UserAttributeChangedEvent.class));
    }
}
