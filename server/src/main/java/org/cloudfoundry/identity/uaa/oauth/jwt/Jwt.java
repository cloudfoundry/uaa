package org.cloudfoundry.identity.uaa.oauth.jwt;

public interface Jwt extends org.springframework.security.jwt.Jwt {
    HeaderParameters getHeader();
}
