package org.cloudfoundry.identity.samples.password;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.cloud.security.oauth2.sso.EnableOAuth2Sso;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;


import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.WebApplicationContext;

@Configuration
@EnableAutoConfiguration
@ComponentScan
@Controller
public class Application {

    public static void main(String[] args) {
        if ("true".equals(System.getenv("SKIP_SSL_VALIDATION"))) {
            org.cloudfoundry.identity.samples.password.SSLValidationDisabler.disableSSLValidation();
        }
        SpringApplication.run(Application.class, args);
    }


    @Value("${idServiceUrl}")
    private String idServiceUrl;

    @Autowired
    @Qualifier("passwordGrantRestTemplate")
    private OAuth2RestTemplate oAuth2RestTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @RequestMapping("/")
    public String index(HttpServletRequest request, Model model) {
        return "index";
    }

    @Autowired
    private ResourceOwnerPasswordResourceDetails passwordGrantResourceDetails;

    @RequestMapping("/password")
    public String showPasswordPage() {
        return "password_form";
    }

    @RequestMapping(value = "/password",method = RequestMethod.POST)
    public String doPasswordLogin(@RequestParam String username, @RequestParam String password, Model model) throws Exception {
//        Tried this http://projects.spring.io/spring-security-oauth/docs/oauth2.html#accessing-protected-resources
//        but there seems to be a bug where the DefaultRequestEnhancer doesn't propagate username and password
//        AccessTokenRequest accessTokenRequest = oAuth2RestTemplate.getOAuth2ClientContext().getAccessTokenRequest();
//        accessTokenRequest.set("username", username);
//        accessTokenRequest.set("password", password);
        passwordGrantResourceDetails.setUsername(username);
        passwordGrantResourceDetails.setPassword(password);
        String response = oAuth2RestTemplate.getForObject("{uaa}/userinfo", String.class,
            idServiceUrl);
        model.addAttribute("response", toPrettyJsonString(response));
        model.addAttribute("token", getToken(oAuth2RestTemplate.getOAuth2ClientContext()));
        return "password_result";
    }

    private Map<String, ?> getToken(OAuth2ClientContext clientContext) throws Exception {
        if (clientContext.getAccessToken() != null) {
            String tokenBase64 = clientContext.getAccessToken().getValue().split("\\.")[1];
            return objectMapper.readValue(Base64.decodeBase64(tokenBase64), new TypeReference<Map<String, ?>>() {
            });
        }
        return null;
    }

    private String toPrettyJsonString(Object object) throws Exception {
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
    }

    @Bean
    @ConfigurationProperties(prefix = "spring.oauth2.client")
    ResourceOwnerPasswordResourceDetails passwordGrantResourceDetails() {
        return new ResourceOwnerPasswordResourceDetails();
    }

    @Bean
    public OAuth2RestTemplate passwordGrantRestTemplate(OAuth2ClientContext oauth2Context) {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(passwordGrantResourceDetails(), oauth2Context);
        return restTemplate;
    }
}
