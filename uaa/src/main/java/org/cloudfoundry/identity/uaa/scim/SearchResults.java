/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.scim;

import java.util.ArrayList;
import java.util.Collection;

/**
 * @author Dave Syer
 *
 */
public class SearchResults<T> {
	
	private final Collection<T> resources;
	private final int startIndex;
	private final int itemsPerPage;
	private final int totalResults;
	private final Collection<String> schemas;

	public SearchResults(Collection<String> schemas, Collection<T> resources, int startIndex, int itemsPerPage, int totalResults) {
		this.schemas = new ArrayList<String>(schemas);
		this.resources = new ArrayList<T>(resources);
		this.startIndex = startIndex;
		this.itemsPerPage = itemsPerPage;
		this.totalResults = totalResults;
	}
	
	public Collection<String> getSchemas() {
		return schemas;
	}
	
	public int getStartIndex() {
		return startIndex;
	}

	public int getItemsPerPage() {
		return itemsPerPage;
	}

	public int getTotalResults() {
		return totalResults;
	}

	public Collection<T> getResources() {
		return resources;
	}

}
