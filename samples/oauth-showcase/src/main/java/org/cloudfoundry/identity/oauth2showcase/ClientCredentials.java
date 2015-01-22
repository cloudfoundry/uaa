package org.cloudfoundry.identity.oauth2showcase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ClientCredentials {
   
    @Value("${uaa.location}")
    private String uaaLocation;

    @Autowired
    @Qualifier("clientCredentialsRestTemplate")
    private OAuth2RestTemplate clientCredentialsRestTemplate;
    
    @RequestMapping("/client_credentials")
    public String clientCredentials(Model model) throws Exception {
        Object clientResponse = clientCredentialsRestTemplate.getForObject("{uaa}/oauth/clients", Object.class,
                uaaLocation);
        model.addAttribute("clients", clientResponse);
        model.addAttribute("token", Utils.getToken(clientCredentialsRestTemplate.getOAuth2ClientContext()));
        return "client_credentials";
    }

    @Configuration
    @EnableConfigurationProperties
    @EnableOAuth2Client
    public static class Config {
        @Bean
        @ConfigurationProperties(prefix = "oauth_clients.client_credentials")
        ClientCredentialsResourceDetails clientCredentialsResourceDetails() {
            return new ClientCredentialsResourceDetails();
        }

        @Bean
        OAuth2RestTemplate clientCredentialsRestTemplate() {
            OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(clientCredentialsResourceDetails());
            return restTemplate;
        }
    }


}
