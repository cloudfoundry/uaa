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

package org.cloudfoundry.identity.uaa.rest.jdbc;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.StringUtils;

public class SimpleSearchQueryConverter implements SearchQueryConverter {

    private static Log logger = LogFactory.getLog(SimpleSearchQueryConverter.class);
    private AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.<String, String> emptyMap());

    public void setAttributeNameMapper(AttributeNameMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public ProcessedFilter convert(String filter, String sortBy, boolean ascending) {
        return convert(filter, sortBy, ascending, mapper);
    }

    @Override
    public ProcessedFilter convert(String filter, String sortBy, boolean ascending, AttributeNameMapper mapper) {
        String paramPrefix = generateParameterPrefix(filter);
        Map<String, Object> values = new HashMap<String, Object>();
        String where = StringUtils.hasText(filter) ? getWhereClause(filter, sortBy, ascending, values, mapper, paramPrefix) : null;
        ProcessedFilter pf = new ProcessedFilter(where, values);
        pf.setParamPrefix(paramPrefix);
        return pf;
    }

    protected String generateParameterPrefix(String filter) {
        while (true) {
            String s = new RandomValueStringGenerator().generate().toLowerCase();
            if (!filter.contains(s)) {
                return "__"+s+"_";
            }
        }
    }

    private String getWhereClause(String filter, String sortBy, boolean ascending, Map<String, Object> values, AttributeNameMapper mapper, String paramPrefix) {

        try {
            SCIMFilter scimFilter = SCIMFilter.parse(filter);
            String whereClause = createFilter(scimFilter, values, mapper, paramPrefix);
            if (sortBy != null) {
                sortBy = mapper.mapToInternal(sortBy);
                // Need to add "asc" or "desc" explicitly to ensure that the pattern
                // splitting below works
                whereClause += " ORDER BY " + sortBy + (ascending ? " ASC" : " DESC");
            }
            return whereClause;
        } catch (SCIMException e) {
            logger.debug("Unable to parse " + filter, e);
            throw new IllegalArgumentException("Invalid SCIM Filter:"+filter+" Message:"+e.getMessage());
        }
    }

    private String createFilter(SCIMFilter filter, Map<String,Object> values, AttributeNameMapper mapper, String paramPrefix) {
        switch (filter.getFilterType()) {
            case AND:
                return "(" + createFilter(filter.getFilterComponents().get(0), values, mapper, paramPrefix) + " AND " + createFilter(filter.getFilterComponents().get(1), values, mapper, paramPrefix) + ")";
            case OR:
                return "(" + createFilter(filter.getFilterComponents().get(0), values, mapper, paramPrefix) + " OR " + createFilter(filter.getFilterComponents().get(1), values, mapper, paramPrefix) + ")";
            case EQUALITY:
                return comparisonClause(filter, "=", values, "", "", paramPrefix);
            case CONTAINS:
                return comparisonClause(filter, "LIKE", values, "%", "%", paramPrefix);
            case STARTS_WITH:
                return comparisonClause(filter, "LIKE", values, "", "%", paramPrefix);
            case PRESENCE:
                return getAttributeName(filter, mapper) + " IS NOT NULL";
            case GREATER_THAN:
                return comparisonClause(filter, ">", values, "", "", paramPrefix);
            case GREATER_OR_EQUAL:
                return comparisonClause(filter, ">=", values, "", "", paramPrefix);
            case LESS_THAN:
                return comparisonClause(filter, "<", values, "", "", paramPrefix);
            case LESS_OR_EQUAL:
                return comparisonClause(filter, "<=", values, "", "", paramPrefix);
        }
        return null;
    }

    protected String comparisonClause(SCIMFilter filter, String comparator, Map<String, Object> values, String valuePrefix, String valueSuffix, String paramPrefix) {
        String pName = getParamName(filter, values, paramPrefix);
        String paramName = ":"+pName;
        if (filter.getFilterValue() == null) {
            return getAttributeName(filter, mapper) + " IS NULL";
        } else if (filter.isQuoteFilterValue()) {
            Object value = getStringOrDate(filter.getFilterValue());
            if (value instanceof String) {
                //TODO - why lower?
                values.put(pName, valuePrefix+value+valueSuffix);
                return "LOWER(" + getAttributeName(filter, mapper) + ") "+comparator+" LOWER(" + paramName+")";
            } else {
                values.put(pName, value);
                return getAttributeName(filter, mapper) + " "+comparator+" " + paramName;
            }


        } else {
            try {
                values.put(pName, Double.parseDouble(filter.getFilterValue()));
            } catch (NumberFormatException x) {
                values.put(pName, filter.getFilterValue());
            }
            return getAttributeName(filter, mapper) + " "+comparator+" " + paramName;
        }
    }

    protected String getAttributeName(SCIMFilter filter, AttributeNameMapper mapper) {
        String name = filter.getFilterAttribute().getAttributeName();
        String subName = filter.getFilterAttribute().getSubAttributeName();
        if (StringUtils.hasText(subName)) {
            name = name + "." + subName;
        }
        name = mapper.mapToInternal(name);
        return name.replace("meta.", "");
    }

    protected String getParamName(SCIMFilter filter, Map<String, Object> values, String paramPrefix) {
        return paramPrefix+values.size();
    }

    protected Object getStringOrDate(String s) {
        try {
            DateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            return TIMESTAMP_FORMAT.parse(s);
        } catch (ParseException x) {
            return s;
        }
    }



}
