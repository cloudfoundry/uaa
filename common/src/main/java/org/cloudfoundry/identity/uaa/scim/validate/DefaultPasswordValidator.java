/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.scim.validate;

import edu.vt.middleware.dictionary.ArrayWordList;
import edu.vt.middleware.dictionary.WordListDictionary;
import edu.vt.middleware.dictionary.WordLists;
import edu.vt.middleware.password.AlphabeticalCharacterRule;
import edu.vt.middleware.password.AlphabeticalSequenceRule;
import edu.vt.middleware.password.DictionarySubstringRule;
import edu.vt.middleware.password.DigitCharacterRule;
import edu.vt.middleware.password.LengthRule;
import edu.vt.middleware.password.NumericalSequenceRule;
import edu.vt.middleware.password.Password;
import edu.vt.middleware.password.PasswordData;
import edu.vt.middleware.password.QwertySequenceRule;
import edu.vt.middleware.password.RegexRule;
import edu.vt.middleware.password.RepeatCharacterRegexRule;
import edu.vt.middleware.password.Rule;
import edu.vt.middleware.password.RuleResult;
import edu.vt.middleware.password.UsernameRule;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A standard password validator built using vt-password rules.
 *
 * @author Luke Taylor
 */
public class DefaultPasswordValidator implements PasswordValidator {
	private final List<Rule> defaultRules;
    private final List<Rule> shortRules;

	public DefaultPasswordValidator() {
		List<Rule> rules = new ArrayList<Rule>(6);
		rules.add(new LengthRule(10, 50));
		rules.add(new DigitCharacterRule());
		rules.add(new AlphabeticalCharacterRule());
		rules.add(new UsernameRule(true, true));
		// Try and catch variations on "password" as a password
		rules.add(new RegexRule("[pP]+[aA@&]*[sSzZ$]+[wW]+[oO0]*[rR]*[dD]*"));
		rules.add(new QwertySequenceRule());

        defaultRules = Collections.unmodifiableList(rules);

        rules = new ArrayList<Rule>(3);

        rules.add(new NumericalSequenceRule());
        rules.add(new RepeatCharacterRegexRule());
        rules.add(new AlphabeticalSequenceRule());

        shortRules = Collections.unmodifiableList(rules);
    }

	@Override
	public void validate(String password, ScimUser user) throws InvalidPasswordException {
		List<Rule> rules;

		PasswordData passwordData = new PasswordData(new Password(password));
		passwordData.setUsername(user.getUserName());

		// Build dictionary rule based on Scim data
		rules = new ArrayList<Rule>(defaultRules);
        if (password.length() < 20) {
            // Check sequences only in "short" passwords (see CFID-221)
            rules.addAll(shortRules);
        }
		String[] userWords = user.wordList().toArray(new String[user.wordList().size()]);
		Arrays.sort(userWords, WordLists.CASE_INSENSITIVE_COMPARATOR);
		rules.add(new DictionarySubstringRule(new WordListDictionary(new ArrayWordList(userWords, false))));

		edu.vt.middleware.password.PasswordValidator validator =
				new edu.vt.middleware.password.PasswordValidator(rules);

		RuleResult result = validator.validate(passwordData);

		if (!result.isValid()) {
			String errors = StringUtils.collectionToDelimitedString(validator.getMessages(result), ",");

			throw new InvalidPasswordException(errors);
		}
	}


}
