/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class IdentityZoneHolderTest {

    private BrandingInformation zoneBranding;
    private BrandingInformation defaultZoneBranding;
    private IdentityZone fakeUaa;

    @Before
    public void setUp() throws Exception {
        defaultZoneBranding = new BrandingInformation();
        defaultZoneBranding.setProductLogo("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABSUlEQVQ4EaVTO04DMRB9YdOTC+QcK46w" +
                                               "FU3apclKuQMH4AYUkUxFmyY0PgLac3AB6ImM3kyePYkQDZZ27Zl58+aNP8A/x2J7ixI5Xr6wiHaMX8eIW/L3/tlStisUAZm8fx1acMxWTPFK0BBOR" +
                                               "hL5ukP2ZQ9UsjHXIqZA4LuVrwjsPjxxenRfAtAh47QenCiQgFL5fb8NpTyjlAf/5KOfa/llk/pG1WvV2T3T0We1wLh8jNAmaSUwyTMMRGC6dxDXIl" +
                                               "ExtUd7SZb0BKhXU3LIRrTfKKXNpsLU+R7VTWTFKJEpuzGbktNmuFiLjnEj4M52s4OnMVt/CedTYLWjx9Artc1269hG3MSohMps9LAjVCqrc9QWaJg" +
                                               "SZCRWOp+GoX5J5u3lvan3nioIphIOnQr711BVXf0LAoGuieRnMt8A438SKEFEsuMDirEf/oirUgza/ucAAAAASUVORK5CYII=");

        zoneBranding = new BrandingInformation();
        zoneBranding.setProductLogo("zoneBrandingString===");

        fakeUaa = IdentityZoneHolder.getUaaZone();
        fakeUaa.getConfig().setBranding(defaultZoneBranding);

        IdentityZoneProvisioning provisioning = Mockito.mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);

        Mockito.when(provisioning.retrieve(fakeUaa.getId())).thenReturn(fakeUaa);
    }

    @Test
    public void getProductLogoForZone() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        IdentityZoneHolder.get().getConfig().setBranding(zoneBranding);

        BrandingInformationSource brandingInformationSource = IdentityZoneHolder.resolveBranding();
        assertEquals(brandingInformationSource.getProductLogo(), zoneBranding.getProductLogo());
    }

    @Test
    public void emptyProductLogoForZoneDoesNotReturnDefault() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        IdentityZoneHolder.get().getConfig().setBranding(new BrandingInformation());

        BrandingInformationSource brandingInformationSource = IdentityZoneHolder.resolveBranding();
        assertNull(brandingInformationSource.getProductLogo());
    }

    @Test
    public void getProductLogoForDefaultZoneReturnsDefaultLogo() {
        IdentityZoneHolder.set(fakeUaa);

        BrandingInformationSource brandingInformationSource = IdentityZoneHolder.resolveBranding();
        assertEquals(brandingInformationSource.getProductLogo(), defaultZoneBranding.getProductLogo());
    }

    @Test
    public void deserialize() throws Exception {
        String json = "{\n" +
            "  \"id\": \"f7758816-ab47-48d9-9d24-25b10b92d4cc\",\n" +
            "  \"subdomain\": \"demo\",\n" +
            "  \"config\": {\n" +
            "    \"clientSecretPolicy\": {\n" +
            "      \"minLength\": -1,\n" +
            "      \"maxLength\": -1,\n" +
            "      \"requireUpperCaseCharacter\": -1,\n" +
            "      \"requireLowerCaseCharacter\": -1,\n" +
            "      \"requireDigit\": -1,\n" +
            "      \"requireSpecialCharacter\": -1\n" +
            "    },\n" +
            "    \"tokenPolicy\": {\n" +
            "      \"accessTokenValidity\": -1,\n" +
            "      \"refreshTokenValidity\": -1,\n" +
            "      \"jwtRevocable\": false,\n" +
            "      \"refreshTokenUnique\": false,\n" +
            "      \"refreshTokenFormat\": \"jwt\",\n" +
            "      \"activeKeyId\": null\n" +
            "    },\n" +
            "    \"samlConfig\": {\n" +
            "      \"assertionSigned\": true,\n" +
            "      \"requestSigned\": true,\n" +
            "      \"wantAssertionSigned\": true,\n" +
            "      \"wantAuthnRequestSigned\": false,\n" +
            "      \"assertionTimeToLiveSeconds\": 600,\n" +
            "      \"keys\": {\n" +
            "      },\n" +
            "      \"disableInResponseToCheck\": true\n" +
            "    },\n" +
            "    \"corsPolicy\": {\n" +
            "      \"xhrConfiguration\": {\n" +
            "        \"allowedOrigins\": [\n" +
            "          \".*\"\n" +
            "        ],\n" +
            "        \"allowedOriginPatterns\": [\n" +
            "\n" +
            "        ],\n" +
            "        \"allowedUris\": [\n" +
            "          \".*\"\n" +
            "        ],\n" +
            "        \"allowedUriPatterns\": [\n" +
            "\n" +
            "        ],\n" +
            "        \"allowedHeaders\": [\n" +
            "          \"Accept\",\n" +
            "          \"Authorization\",\n" +
            "          \"Content-Type\"\n" +
            "        ],\n" +
            "        \"allowedMethods\": [\n" +
            "          \"GET\"\n" +
            "        ],\n" +
            "        \"allowedCredentials\": false,\n" +
            "        \"maxAge\": 1728000\n" +
            "      },\n" +
            "      \"defaultConfiguration\": {\n" +
            "        \"allowedOrigins\": [\n" +
            "          \".*\"\n" +
            "        ],\n" +
            "        \"allowedOriginPatterns\": [\n" +
            "\n" +
            "        ],\n" +
            "        \"allowedUris\": [\n" +
            "          \".*\"\n" +
            "        ],\n" +
            "        \"allowedUriPatterns\": [\n" +
            "\n" +
            "        ],\n" +
            "        \"allowedHeaders\": [\n" +
            "          \"Accept\",\n" +
            "          \"Authorization\",\n" +
            "          \"Content-Type\"\n" +
            "        ],\n" +
            "        \"allowedMethods\": [\n" +
            "          \"GET\"\n" +
            "        ],\n" +
            "        \"allowedCredentials\": false,\n" +
            "        \"maxAge\": 1728000\n" +
            "      }\n" +
            "    },\n" +
            "    \"links\": {\n" +
            "      \"logout\": {\n" +
            "        \"redirectUrl\": \"/login\",\n" +
            "        \"redirectParameterName\": \"redirect\",\n" +
            "        \"disableRedirectParameter\": false,\n" +
            "        \"whitelist\": null\n" +
            "      },\n" +
            "      \"selfService\": {\n" +
            "        \"selfServiceLinksEnabled\": true,\n" +
            "        \"signup\": null,\n" +
            "        \"passwd\": null\n" +
            "      }\n" +
            "    },\n" +
            "    \"prompts\": [\n" +
            "      {\n" +
            "        \"name\": \"username\",\n" +
            "        \"type\": \"text\",\n" +
            "        \"text\": \"Email\"\n" +
            "      },\n" +
            "      {\n" +
            "        \"name\": \"password\",\n" +
            "        \"type\": \"password\",\n" +
            "        \"text\": \"Password\"\n" +
            "      },\n" +
            "      {\n" +
            "        \"name\": \"passcode\",\n" +
            "        \"type\": \"password\",\n" +
            "        \"text\": \"Temporary Authentication Code (Get on at /passcode)\"\n" +
            "      }\n" +
            "    ],\n" +
            "    \"idpDiscoveryEnabled\": false,\n" +
            "    \"accountChooserEnabled\": false,\n" +
            "    \"userConfig\": {\n" +
            "      \"defaultGroups\": [\n" +
            "        \"openid\",\n" +
            "        \"password.write\",\n" +
            "        \"uaa.user\",\n" +
            "        \"approvals.me\",\n" +
            "        \"profile\",\n" +
            "        \"roles\",\n" +
            "        \"user_attributes\",\n" +
            "        \"uaa.offline_token\"\n" +
            "      ]\n" +
            "    }\n" +
            "  },\n" +
            "  \"name\": \"Demo Login Page\",\n" +
            "  \"version\": 1,\n" +
            "  \"description\": \"{\\\"plan_display_name\\\":\\\"Demo\\\",\\\"plan_description\\\":\\\"Demo SSO Plan\\\"}\",\n" +
            "  \"created\": 1503504273000,\n" +
            "  \"last_modified\": 1504898224000\n" +
            "}";
        IdentityZone zone = JsonUtils.readValue(json, IdentityZone.class);
    }
}
