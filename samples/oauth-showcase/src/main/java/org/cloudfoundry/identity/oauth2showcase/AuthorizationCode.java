package org.cloudfoundry.identity.oauth2showcase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.security.oauth2.sso.EnableOAuth2Sso;
import org.springframework.cloud.security.oauth2.sso.OAuth2SsoConfigurerAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class AuthorizationCode {
    @Value("${uaa.location}")
    private String uaaLocation;
    
    @Autowired
    @Qualifier("oauth2RestTemplate")
    private OAuth2RestTemplate authcodeRestTemplate;

    @RequestMapping("/authorization_code")
    public String authCode(Model model) {
        String response = authcodeRestTemplate.getForObject("{uaa}/userinfo", String.class,
                uaaLocation);
        model.addAttribute("response", Utils.toPrettyJsonString(response));
        model.addAttribute("token", Utils.getToken(authcodeRestTemplate.getOAuth2ClientContext()));
        return "authorization_code";
    }

    @Configuration
    @EnableOAuth2Sso
    public static class Config {
        @Bean
        OAuth2SsoConfigurerAdapter oAuth2SsoConfigurerAdapter() {
            return new OAuth2SsoConfigurerAdapter() {
                @Override
                public void match(RequestMatchers matchers) {
                    matchers.antMatchers("/authorization_code/**");
                }

                public void configure(HttpSecurity http) throws Exception {
                    http.authorizeRequests()
                            .antMatchers("/").permitAll();
                }
            };
        }
    }

}
