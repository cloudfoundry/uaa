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
package org.cloudfoundry.identity.uaa.login.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;

public class FileLocator {

    public static File locate(String filename) throws IOException {
        File f = new File(filename);
        //try file system
        if (f.exists()) {
            return f;
        }
        //try classloader
        URL url = Thread.currentThread().getContextClassLoader().getResource( filename );
        if ( url != null && url.getFile() != null && (new File(url.getFile()).exists()) ) {
            return new File(url.getFile());
        }
        throw new FileNotFoundException( "Cannot find resource on file system or classpath: '" + filename + "'" );
    }
}
