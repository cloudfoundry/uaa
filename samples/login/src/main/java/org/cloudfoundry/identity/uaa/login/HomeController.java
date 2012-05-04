package org.cloudfoundry.identity.uaa.login;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

	@RequestMapping(value={"/", "/home"})
	public String home(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		return "home";
	}

}
