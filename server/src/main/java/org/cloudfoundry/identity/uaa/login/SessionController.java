
package org.cloudfoundry.identity.uaa.login;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SessionController {

    @RequestMapping("/session")
    public String session(Model model, @RequestParam String clientId, @RequestParam String messageOrigin) {
        // We need to maintain this version of the session page to continue compatibility with the
        // original version of uaa-singular.
        model.addAttribute("clientId", clientId);
        model.addAttribute("messageOrigin", messageOrigin);
        return "session";
    }

    @RequestMapping("/session_management")
    public String sessionManagement(Model model, @RequestParam String clientId, @RequestParam String messageOrigin) {
        model.addAttribute("clientId", clientId);
        model.addAttribute("messageOrigin", messageOrigin);
        return "session_management";
    }
}
