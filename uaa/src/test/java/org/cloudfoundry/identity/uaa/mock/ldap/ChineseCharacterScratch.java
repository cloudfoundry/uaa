/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.ldap;

import java.util.Arrays;

public class ChineseCharacterScratch {
    public static void main(String[] args) {
        String s = "\u7433\u8D3A";
        System.out.println("1. "+s);
        System.out.println("Length:"+  s);
        System.out.println("Chars:"+ Arrays.toString(getInts(s)));


    }

    public static int[] getInts(String s) {
        char[] array = s.toCharArray();
        int[] result = new int[array.length];
        for (int i=0; i<array.length; i++) {
            result[i] = (int)(array[i]);
        }
        return result;
    }
}
