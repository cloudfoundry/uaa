package org.cloudfoundry.identity.samples.clientcredentials;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${idServiceUrl}")
    private String uaaLocation;

    @Autowired
    @Qualifier("clientCredentialsRestTemplate")
    private OAuth2RestTemplate clientCredentialsRestTemplate;
    
    @RequestMapping("/")
    public String index(HttpServletRequest request, Model model) {
        return "index";
    }

    @RequestMapping("/client_credentials")
    public String clientCredentials(Model model) throws Exception {
        Object clientResponse = clientCredentialsRestTemplate.getForObject("{uaa}/oauth/clients", Object.class,
                uaaLocation);
        model.addAttribute("clients", clientResponse);
        model.addAttribute("token", getToken(clientCredentialsRestTemplate.getOAuth2ClientContext()));
        return "client_credentials";
    }

    @Configuration
    @EnableConfigurationProperties
    @EnableOAuth2Client
    public static class Config {
        @Bean
        @ConfigurationProperties(prefix = "spring.oauth2.client")
        ClientCredentialsResourceDetails clientCredentialsResourceDetails() {
            return new ClientCredentialsResourceDetails();
        }

        @Bean
        OAuth2RestTemplate clientCredentialsRestTemplate() {
            OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(clientCredentialsResourceDetails());
            return restTemplate;
        }
    }
    
    private Map<String, ?> getToken(OAuth2ClientContext clientContext) throws Exception {
        if (clientContext.getAccessToken() != null) {
            String tokenBase64 = clientContext.getAccessToken().getValue().split("\\.")[1];
            return objectMapper.readValue(Base64.decodeBase64(tokenBase64), new TypeReference<Map<String, ?>>() {
            });
        }
        return null;
    }
}