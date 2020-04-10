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
