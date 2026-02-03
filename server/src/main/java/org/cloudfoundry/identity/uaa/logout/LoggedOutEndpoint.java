package org.cloudfoundry.identity.uaa.logout;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoggedOutEndpoint {

    @GetMapping("/logged_out")
    public String loggedOut() {
        return "logged_out";
    }

}
