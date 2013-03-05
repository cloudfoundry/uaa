package org.cloudfoundry.identity.uaa.util;

import java.util.List;

public class UaaPagingUtils {

	/**
	 * Calculates the substring of a list based on a 1 based start index never exceeding
	 * the bounds of the list. 
	 * @param input
	 * @param startIndex
	 * @param count
	 * @return
	 */
	public static <T> List<T> subList(List<T> input, int startIndex, int count) {
		int fromIndex = startIndex-1;
		int toIndex = fromIndex+count;
		if(toIndex >= input.size()) {
			toIndex = input.size();
		}
		return input.subList(fromIndex, toIndex);
	}
}
