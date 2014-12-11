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
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

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
    @Qualifier("oauth2RestTemplate")
    private OAuth2RestTemplate authcodeRestTemplate;

    @Autowired
    @Qualifier("uaaClientCredentialsRestTemplate")
    private OAuth2RestTemplate clientCredentialsRestTemplate;
    
    @Autowired
    @Qualifier("uaaPasswordGrantRestTemplate")
    private OAuth2RestTemplate passwordGrantRestTemplate;
    @Autowired
    private ResourceOwnerPasswordResourceDetails passwordGrantResourceDetails;

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
    public String index(HttpServletRequest request, Model model) {
        request.getSession().invalidate();
        model.addAttribute("thisUrl", UrlUtils.buildFullRequestUrl(request));
        return "index";
    }

    @RequestMapping("/authorization_code")
    public String authCode(Model model) {
        String jsonFromUaa = getJsonFromUaa(authcodeRestTemplate, "userinfo");
        model.addAttribute("response", jsonFromUaa);
        addTokenToModel(model);
        return "authorization_code";
    }
    
    @RequestMapping("/password")
    
    public String showPasswordPage() {
        return "password";
    }
    
    @RequestMapping(value = "/password",method = RequestMethod.POST)
    public String doPasswordLogin(@RequestParam String username, @RequestParam String password, Model model) {
        passwordGrantResourceDetails.setUsername(username);
        passwordGrantResourceDetails.setPassword(password);
        String jsonFromUaa = getJsonFromUaa(passwordGrantRestTemplate, "userinfo");
        model.addAttribute("response", jsonFromUaa);
        addTokenToModel(model);
        return "after_password";
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
    
    public String getJsonFromUaa(OAuth2RestTemplate restTemplate, String path) {
        try {
            String clientResponse = restTemplate.getForObject("{uaa}/{path}", String.class,
                    uaaLocation,path);
            return prettyPrintJson(clientResponse);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String prettyPrintJson(String json) {
        try {
            Object object = objectMapper.readValue(json, Object.class);
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
    }
}
