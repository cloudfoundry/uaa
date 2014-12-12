package org.cloudfoundry.identity.oauth2showcase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PasswordGrant {
   
    @Value("${uaa.location}")
    private String uaaLocation;

    @Autowired
    @Qualifier("passwordGrantRestTemplate")
    private OAuth2RestTemplate oAuth2RestTemplate;
    
    @RequestMapping("/password")
    public String showPasswordPage() {
        return "password_form";
    }
    
    @RequestMapping(value = "/password",method = RequestMethod.POST)
    public String doPasswordLogin(@RequestParam String username, @RequestParam String password, Model model) {
        AccessTokenRequest accessTokenRequest = oAuth2RestTemplate.getOAuth2ClientContext().getAccessTokenRequest();
        accessTokenRequest.set("username", username);
        accessTokenRequest.set("password", password);
        String response = oAuth2RestTemplate.getForObject("{uaa}/userinfo", String.class,
                uaaLocation);
        model.addAttribute("response", Utils.toPrettyJsonString(response));
        model.addAttribute("token", Utils.getToken(oAuth2RestTemplate.getOAuth2ClientContext()));
       return "password_result";
    }
    
    @Configuration
    @EnableOAuth2Client
    public static class Config {
        @Bean
        @ConfigurationProperties(prefix = "oauth_clients.password_grant")
        ResourceOwnerPasswordResourceDetails passwordGrantResourceDetails() {
            return new ResourceOwnerPasswordResourceDetails();
        }

        @Bean
        public OAuth2RestTemplate passwordGrantRestTemplate(OAuth2ClientContext oauth2Context) {
            OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(passwordGrantResourceDetails(), oauth2Context);
            return restTemplate;
        }
    }


}
