package org.cloudfoundry.identity.uaa.logout;

import org.junit.jupiter.api.Test;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class LoggedOutEndpointTest {

    @Test
    void loggedOutMethod_shouldAddAttributesToModelWithDefaultValues() {
        // Unit test for the controller method directly with default values
        LoggedOutEndpoint controller = new LoggedOutEndpoint(
                "You have successfully logged out.",
                "Back to Sign In",
                "/login"
        );
        
        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", "You have successfully logged out.");
        verify(model).addAttribute("linkText", "Back to Sign In");
        verify(model).addAttribute("linkUrl", "/login");
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void loggedOutMethod_shouldAddAttributesToModelWithCustomValues() {
        // Test that constructor properly stores the injected configuration values
        String expectedMessage = "Custom logout message";
        String expectedLinkText = "Custom link text";
        String expectedLinkUrl = "https://custom.example.com/login";

        LoggedOutEndpoint controller = new LoggedOutEndpoint(
                expectedMessage,
                expectedLinkText,
                expectedLinkUrl
        );

        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", expectedMessage);
        verify(model).addAttribute("linkText", expectedLinkText);
        verify(model).addAttribute("linkUrl", expectedLinkUrl);
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void loggedOutMethod_shouldHandleNullValues() {
        // Test with null values (edge case)
        LoggedOutEndpoint controller = new LoggedOutEndpoint(null, null, null);

        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", null);
        verify(model).addAttribute("linkText", null);
        verify(model).addAttribute("linkUrl", null);
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void loggedOutMethod_shouldHandleEmptyValues() {
        // Test with empty string values
        LoggedOutEndpoint controller = new LoggedOutEndpoint("", "", "");

        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", "");
        verify(model).addAttribute("linkText", "");
        verify(model).addAttribute("linkUrl", "");
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void loggedOutMethod_shouldHandleSpecialCharacters() {
        // Test that constructor handles special characters in configuration values
        String messageWithSpecialChars = "You've successfully logged out! <script>alert('test')</script>";
        String linkTextWithSpecialChars = "« Back to Sign In »";
        String linkUrlWithSpecialChars = "https://example.com/login?redirect=https%3A%2F%2Fapp.example.com";

        LoggedOutEndpoint controller = new LoggedOutEndpoint(
                messageWithSpecialChars,
                linkTextWithSpecialChars,
                linkUrlWithSpecialChars
        );

        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", messageWithSpecialChars);
        verify(model).addAttribute("linkText", linkTextWithSpecialChars);
        verify(model).addAttribute("linkUrl", linkUrlWithSpecialChars);
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void constructor_shouldAcceptConfigurationValues() {
        // Test that constructor accepts and stores configuration values
        String message = "Test message";
        String linkText = "Test link text";
        String linkUrl = "Test URL";

        LoggedOutEndpoint controller = new LoggedOutEndpoint(message, linkText, linkUrl);
        
        // Verify by calling the method and checking the model attributes
        Model model = mock(Model.class);
        controller.loggedOut(model);

        verify(model).addAttribute("message", message);
        verify(model).addAttribute("linkText", linkText);
        verify(model).addAttribute("linkUrl", linkUrl);
    }
}