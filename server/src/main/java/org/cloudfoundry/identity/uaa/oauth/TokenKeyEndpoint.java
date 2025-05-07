package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeysListResponse;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;

/**
 * OAuth2 token services that produces JWT encoded token values.
 */
@Controller
public class TokenKeyEndpoint {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final KeyInfoService keyInfoService;

    public TokenKeyEndpoint(
            final @Qualifier("keyInfoService") KeyInfoService keyInfoService) {
        this.keyInfoService = keyInfoService;
    }

    @GetMapping("/token_key")
    @ResponseBody
    public ResponseEntity<VerificationKeyResponse> getKey(Principal principal,
                                                          @RequestHeader(value = "If-None-Match", required = false, defaultValue = "NaN") String eTag) {
        String lastModified = ((Long) IdentityZoneHolder.get().getLastModified().getTime()).toString();
        if (unmodifiedResource(eTag, lastModified)) {
            return new ResponseEntity<>(HttpStatus.NOT_MODIFIED);
        }

        HttpHeaders header = new HttpHeaders();
        header.put("ETag", Collections.singletonList(lastModified));
        return new ResponseEntity<>(getKey(principal), header, HttpStatus.OK);
    }


    @GetMapping("/token_keys")
    @ResponseBody
    public ResponseEntity<VerificationKeysListResponse> getKeys(Principal principal,
                                                                @RequestHeader(value = "If-None-Match", required = false, defaultValue = "NaN") String eTag) {
        String lastModified = ((Long) IdentityZoneHolder.get().getLastModified().getTime()).toString();
        if (unmodifiedResource(eTag, lastModified)) {
            return new ResponseEntity<>(HttpStatus.NOT_MODIFIED);
        }

        HttpHeaders header = new HttpHeaders();
        header.put("ETag", Collections.singletonList(lastModified));
        return new ResponseEntity<>(getKeys(principal), header, HttpStatus.OK);
    }

    /**
     * Get the verification key for the token signatures. The principal has to
     * be provided only if the key is secret
     * (shared not public).
     *
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens
     */
    public VerificationKeyResponse getKey(Principal principal) {
        KeyInfo key = keyInfoService.getActiveKey();
        if (!includeSymmetricalKeys(principal) && !RSA.name().equals(key.type())) {
            throw new AccessDeniedException("You need to authenticate to see a shared key");
        }
        return getVerificationKeyResponse(key);
    }

    public static VerificationKeyResponse getVerificationKeyResponse(KeyInfo key) {
        return new VerificationKeyResponse(getResultMap(key));
    }

    public static Map<String, Object> getResultMap(KeyInfo key) {
        return key.getJwkMap();
    }

    private boolean unmodifiedResource(String eTag, String lastModified) {
        return !"NaN".equals(eTag) && lastModified.equals(eTag);
    }

    /**
     * Get the verification key for the token signatures wrapped into keys array.
     * Wrapping done for compatibility with some clients expecting this even for single key, like mod_auth_openidc.
     * The principal has to be provided only if the key is secret
     * (shared not public).
     *
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens, wrapped in keys array
     */
    public VerificationKeysListResponse getKeys(Principal principal) {
        boolean includeSymmetric = includeSymmetricalKeys(principal);
        Map<String, KeyInfo> keys = keyInfoService.getKeys();
        List<VerificationKeyResponse> keyResponses = keys.values().stream()
                .filter(k -> includeSymmetric || RSA.name().equals(k.type()))
                .map(TokenKeyEndpoint::getVerificationKeyResponse)
                .toList();
        return new VerificationKeysListResponse(keyResponses);
    }

    protected boolean includeSymmetricalKeys(Principal principal) {
        if (principal != null) {
            if (principal instanceof AnonymousAuthenticationToken) {
                return false;
            } else if (principal instanceof Authentication auth) {
                if (auth.getAuthorities() != null) {
                    for (GrantedAuthority authority : auth.getAuthorities()) {
                        if ("uaa.resource".equals(authority.getAuthority())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

}
