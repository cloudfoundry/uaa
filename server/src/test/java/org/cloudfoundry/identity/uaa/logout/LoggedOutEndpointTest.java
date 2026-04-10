package org.cloudfoundry.identity.uaa.logout;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
        verify(model).addAttribute("linkUrl", expectedLinkUrl); // Valid HTTPS URL should pass validation
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void loggedOutMethod_shouldHandleNullValues() {
        // Test with null values (edge case) - linkUrl should fallback to /login
        LoggedOutEndpoint controller = new LoggedOutEndpoint(null, null, null);

        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", null);
        verify(model).addAttribute("linkText", null);
        verify(model).addAttribute("linkUrl", "/login"); // URL validation fallback
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @Test
    void loggedOutMethod_shouldHandleEmptyValues() {
        // Test with empty string values - linkUrl should fallback to /login
        LoggedOutEndpoint controller = new LoggedOutEndpoint("", "", "");

        Model model = mock(Model.class);
        String viewName = controller.loggedOut(model);

        verify(model).addAttribute("message", "");
        verify(model).addAttribute("linkText", "");
        verify(model).addAttribute("linkUrl", "/login"); // URL validation fallback
        
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
        verify(model).addAttribute("linkUrl", linkUrlWithSpecialChars); // Valid HTTPS URL should pass validation
        
        assertThat(viewName).isEqualTo("logged_out");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "vbscript:msgbox('xss')",
            "file:///etc/passwd",
            "ftp://example.com/file",
            "mailto:user@example.com",
            "tel:+1234567890"
    })
    void constructor_shouldValidateAndSanitizeDangerousUrls(String dangerousUrl) {
        // Test XSS prevention - dangerous schemes should be rejected
        LoggedOutEndpoint controller = new LoggedOutEndpoint("msg", "text", dangerousUrl);

        Model model = mock(Model.class);
        controller.loggedOut(model);
        
        verify(model).addAttribute("linkUrl", "/login"); // Should fallback to safe default
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/login",
            "/auth/login", 
            "/app/dashboard",
            "/logout",
            "/uaa/logout",
            "/path/with/multiple/segments"
    })
    void constructor_shouldAllowValidRelativePaths(String validPath) {
        // Test that valid relative paths are allowed
        LoggedOutEndpoint controller = new LoggedOutEndpoint("msg", "text", validPath);

        Model model = mock(Model.class);
        controller.loggedOut(model);
        
        verify(model).addAttribute("linkUrl", validPath);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://example.com/login",
            "https://secure.example.com/auth",
            "https://app.example.com:8443/login?redirect=home",
            "http://localhost:8080/login",
            "https://subdomain.example.org/path/to/login",
            "https://example.com/login#fragment"
    })
    void constructor_shouldAllowValidAbsoluteUrls(String validUrl) {
        // Test that valid HTTP/HTTPS URLs are allowed
        LoggedOutEndpoint controller = new LoggedOutEndpoint("msg", "text", validUrl);

        Model model = mock(Model.class);
        controller.loggedOut(model);
        
        verify(model).addAttribute("linkUrl", validUrl);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not-a-url",
            "relative-without-slash", 
            "://malformed",
            "   ",
            "",
            "http://",
            "https://",
            "invalid-scheme://example.com"
    })
    void constructor_shouldRejectInvalidUrls(String invalidUrl) {
        // Test that malformed URLs are rejected
        LoggedOutEndpoint controller = new LoggedOutEndpoint("msg", "text", invalidUrl);

        Model model = mock(Model.class);
        controller.loggedOut(model);
        
        verify(model).addAttribute("linkUrl", "/login"); // Should fallback
    }

}