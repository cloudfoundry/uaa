package org.cloudfoundry.identity.uaa.logout;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoggedOutEndpoint {

    private final String message;
    private final String linkText;
    private final String linkUrl;

    public LoggedOutEndpoint(
            @Value("${logged_out.message:You have successfully logged out.}") String message,
            @Value("${logged_out.link_text:Back to Sign In}") String linkText,
            @Value("${logged_out.link_url:/login}") String linkUrl) {
        this.message = message;
        this.linkText = linkText;
        this.linkUrl = UaaUrlUtils.validateAndNormalizeSafeUrl(linkUrl, "/login");
    }

    @GetMapping("/logged_out")
    public String loggedOut(Model model) {
        model.addAttribute("message", message);
        model.addAttribute("linkText", linkText);
        model.addAttribute("linkUrl", linkUrl);

        return "logged_out";
    }
}
