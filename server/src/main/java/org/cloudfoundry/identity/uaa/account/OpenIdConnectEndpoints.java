package org.cloudfoundry.identity.uaa.account;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.http.HttpStatus.*;

@Controller
public class OpenIdConnectEndpoints {

    @RequestMapping(value = "/.well-known/openid-configuration")
    public ResponseEntity<OpenIdConfiguration> getOpenIdConfiguration(HttpServletRequest request) {
        OpenIdConfiguration conf = new OpenIdConfiguration(getServerContextPath(request));

        return new ResponseEntity<>(conf, OK);
    }

    private String getServerContextPath(HttpServletRequest request) {
        StringBuffer requestURL = request.getRequestURL();
        return requestURL.substring(0, requestURL.length() - request.getServletPath().length());
    }

}
