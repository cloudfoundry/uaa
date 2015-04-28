package org.cloudfoundry.identity.samples.implicit;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Configuration
@EnableAutoConfiguration
@ComponentScan
@Controller
public class Application {

    public static void main(String[] args) {
        if ("true".equals(System.getenv("SKIP_SSL_VALIDATION"))) {
            SSLValidationDisabler.disableSSLValidation();
        }
        SpringApplication.run(Application.class, args);
    }

    @Value("${idServiceUrl}")
    private String idServiceUrl;

    @RequestMapping("/")
    public String index(HttpServletRequest request, Model model) {
        request.getSession().invalidate();
        model.addAttribute("idServiceUrl", idServiceUrl);
        model.addAttribute("thisUrl", UrlUtils.buildFullRequestUrl(request));
        return "index";
    }
}