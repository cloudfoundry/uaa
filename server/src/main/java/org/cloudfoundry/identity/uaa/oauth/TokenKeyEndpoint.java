/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeysListResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;

/**
 * OAuth2 token services that produces JWT encoded token values.
 *
 */
@Controller
public class TokenKeyEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    /**
     * Get the verification key for the token signatures. The principal has to
     * be provided only if the key is secret
     * (shared not public).
     *
     * @param principal the currently authenticated user if there is one
     * @return the key used to verify tokens
     */
    @RequestMapping(value = "/token_key", method = RequestMethod.GET)
    @ResponseBody
    public VerificationKeyResponse getKey(Principal principal) {
        KeyInfo key = KeyInfo.getActiveKey();
        if (!includeSymmetricalKeys(principal) && !key.isAssymetricKey()) {
            throw new AccessDeniedException("You need to authenticate to see a shared key");
        }
        return getVerificationKeyResponse(key);
    }

    public static VerificationKeyResponse getVerificationKeyResponse(KeyInfo key) {
        Map<String, Object> result = new HashMap<>();
        result.put("alg", key.getSigner().algorithm());
        result.put("value", key.getVerifierKey());
        //new values per OpenID and JWK spec
        result.put("use", sig.name());
        result.put("kid",key.getKeyId());
        result.put("kty", key.getType());

        if (key.isAssymetricKey() && "RSA".equals(key.getType())) {

            RSAPublicKey rsaKey = key.getRsaPublicKey();
            if (rsaKey != null) {
                Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
                String n = encoder.encodeToString(rsaKey.getModulus().toByteArray());
                String e = encoder.encodeToString(rsaKey.getPublicExponent().toByteArray());
                result.put("n", n);
                result.put("e", e);
            }
        }
        return new VerificationKeyResponse(result);
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
    @RequestMapping(value = "/token_keys", method = RequestMethod.GET)
    @ResponseBody
    public VerificationKeysListResponse getKeys(Principal principal) {
        boolean includeSymmetric = includeSymmetricalKeys(principal);
        Map<String, KeyInfo> keys = KeyInfo.getKeys();
        List<VerificationKeyResponse> keyResponses = keys.values().stream()
                .filter(k -> includeSymmetric || k.isAssymetricKey())
                .map(TokenKeyEndpoint::getVerificationKeyResponse)
                .collect(Collectors.toList());
        return new VerificationKeysListResponse(keyResponses);
    }

    protected boolean includeSymmetricalKeys(Principal principal) {
        if (principal!=null) {
            if (principal instanceof AnonymousAuthenticationToken) {
                return false;
            } else if (principal instanceof Authentication) {
                Authentication auth = (Authentication)principal;
                if (auth.getAuthorities()!=null) {
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
