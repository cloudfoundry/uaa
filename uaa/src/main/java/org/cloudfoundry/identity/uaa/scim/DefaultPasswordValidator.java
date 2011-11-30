package org.cloudfoundry.identity.uaa.scim;

import edu.vt.middleware.dictionary.ArrayWordList;
import edu.vt.middleware.dictionary.WordList;
import edu.vt.middleware.dictionary.WordListDictionary;
import edu.vt.middleware.dictionary.WordLists;
import edu.vt.middleware.password.*;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * A standard password validator built using vt-password rules.
 *
 * @author Luke Taylor
 */
public class DefaultPasswordValidator implements PasswordValidator {
	private final List<Rule> defaultRules;

	public DefaultPasswordValidator() {
		List<Rule> rules = new ArrayList<Rule>(6);
		rules.add(new LengthRule(10, 50));
		rules.add(new DigitCharacterRule());
		rules.add(new AlphabeticalCharacterRule());
		rules.add(new UsernameRule(true, true));
		// Try and catch variations on "password" as a password
		rules.add(new RegexRule("[pP]+[aA@&]*[sSzZ$]+[wW]+[oO0]*[rR]*[dD]*"));
		rules.add(new RepeatCharacterRegexRule());
		rules.add(new NumericalSequenceRule());
		rules.add(new AlphabeticalSequenceRule());
		rules.add(new QwertySequenceRule());

		defaultRules = Collections.unmodifiableList(rules);
	}

	@Override
	public void validate(String password, ScimUser user) {
		List<Rule> rules;

		PasswordData passwordData = new PasswordData(new Password(password));
		passwordData.setUsername(user.getUserName());

		// Build dictionary rule based on Scim data
		rules = new ArrayList<Rule>(defaultRules);
		String[] userWords = user.wordList().toArray(new String[user.wordList().size()]);
		Arrays.sort(userWords, WordLists.CASE_INSENSITIVE_COMPARATOR);
		rules.add(new DictionarySubstringRule(new WordListDictionary(new ArrayWordList(userWords, false))));

		edu.vt.middleware.password.PasswordValidator validator =
				new edu.vt.middleware.password.PasswordValidator(rules);


		RuleResult result = validator.validate(passwordData);

		if (!result.isValid()) {
			String errors = StringUtils.collectionToDelimitedString(validator.getMessages(result), ",");

			throw new ScimException(errors, HttpStatus.BAD_REQUEST);
		}
	}


}
