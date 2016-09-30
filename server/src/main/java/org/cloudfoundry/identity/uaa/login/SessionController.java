package org.cloudfoundry.identity.uaa.login;

import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SessionController {

  @RequestMapping("/session")
  public String session(Model model, @RequestParam String clientId, @RequestParam String messageOrigin) {
    model.addAttribute("clientId", clientId);
    model.addAttribute("messageOrigin", messageOrigin);
    return "session";
  }

}
