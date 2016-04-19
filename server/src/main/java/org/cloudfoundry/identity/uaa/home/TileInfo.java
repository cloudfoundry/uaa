/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.home;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TileInfo {

    private ArrayList<LinkedHashMap<String,String>> tiles;

    @Autowired
    public TileInfo(Environment environment) {
        tiles = environment.getProperty("tiles", ArrayList.class, new ArrayList<LinkedHashMap<String,String>>());
    }

    public List<Map<String,String>> getLoginTiles() {
        List<Map<String,String>> loginTiles = new ArrayList<>();
        for (Map<String,String> tile : tiles) {
            if (!StringUtils.isEmpty(tile.get("login-link"))) {
                loginTiles.add(tile);
            }
        }
        return loginTiles;
    }
}
