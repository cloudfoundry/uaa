package org.cloudfoundry.identity.oauth2showcase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

@Configuration
@EnableAutoConfiguration
@ComponentScan
@Controller
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @RequestMapping("/")
    public String index(HttpServletRequest request, Model model) {
        request.getSession().invalidate();
        model.addAttribute("thisUrl", UrlUtils.buildFullRequestUrl(request));
        return "index";
    }
}