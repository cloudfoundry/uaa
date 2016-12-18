/*******************************************************************************
 *     
 *     Copyright (c) [2016] Microsoft, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.resources.jdbc;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
public class SQLServerLimitSqlAdapter implements LimitSqlAdapter {

    @Override
    public String getLimitSql(String sql, int index, int size) {
        Pattern p = Pattern.compile(".+order\\s+by\\s+\\w+(\\s+asc|\\s+desc)?([\\s,]*\\w+(\\s+asc|\\s+desc)?)*\\s*$", Pattern.CASE_INSENSITIVE|Pattern.DOTALL);
		Matcher m = p.matcher(sql);
		if (m.matches()) {
			return sql + " OFFSET " + index + " ROWS FETCH NEXT " + size + " ROWS ONLY;";
		} else {
			return sql + " ORDER BY 1 OFFSET " + index + " ROWS FETCH NEXT " + size + " ROWS ONLY;";
		}
    }

}
