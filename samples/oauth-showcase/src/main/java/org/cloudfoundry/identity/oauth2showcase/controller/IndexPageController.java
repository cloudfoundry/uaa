package org.cloudfoundry.identity.oauth2showcase.controller;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.fasterxml.jackson.databind.ObjectMapper;

@Controller
public class IndexPageController {
    @Autowired
    private ObjectMapper objectMapper;
    @Value("${oauth2.resource.tokenInfoUri}")
    private String tokenInfoEndpoint;
    @Value("${uaa.location}")
    private String uaaLocation;

    @Autowired
    @Qualifier("uaaClientCredentialsRestTemplate")
    private OAuth2RestTemplate clientCredentialsRestTemplate;

    @Autowired
    private OAuth2ClientContext clientContext;

    @RequestMapping("/client_credentials")
    public String clientCredentials(Model model) throws Exception {
        Object clientResponse = clientCredentialsRestTemplate.getForObject("{uaa}/oauth/clients", Object.class,
                uaaLocation);
        model.addAttribute("clients", clientResponse);
        addTokenToModel(model);
        return "client_credentials";
    }

    @RequestMapping("/")
    public String index(HttpServletRequest request) {
        request.getSession().invalidate();
        return "index";
    }

    @RequestMapping("/authorization_code")
    public String authCode(Model model) {
        addTokenToModel(model);
        return "authorization_code";
    }

    public void addTokenToModel(Model model) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            model.addAttribute("authenticated", authentication != null
                    && !(authentication instanceof AnonymousAuthenticationToken));
            model.addAttribute("authentication", authentication);
            if (clientContext.getAccessToken() != null) {
                String tokenBase64 = clientContext.getAccessToken().getValue().split("\\.")[1];
                Object token = objectMapper.readValue(Base64.decodeBase64(tokenBase64), Object.class);
                String tokenString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(token);
                model.addAttribute("token", tokenString);
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

}
