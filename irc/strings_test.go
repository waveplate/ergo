// Copyright (c) 2017 Euan Kemp
// Copyright (c) 2017 Daniel Oaks
// released under the MIT license

package irc

import (
	"fmt"
	"testing"

	"github.com/ergochat/ergo/irc/i18n"
)

var (
	asciiCasemappingOnly = []i18n.Casemapping{i18n.CasemappingASCII}
)

func TestCasefoldChannelAllCasemappings(t *testing.T) {
	oldGlobalCasemapping := globalCasemappingSetting
	t.Cleanup(func() {
		globalCasemappingSetting = oldGlobalCasemapping
	})

	globalCasemappingSetting = i18n.CasemappingPRECIS

	type channelTest struct {
		channel  string
		folded   string
		nonASCII bool
		err      bool
	}
	testCases := []channelTest{
		{
			channel: "#foo",
			folded:  "#foo",
		},
		{
			channel: "#rfc1459[noncompliant]",
			folded:  "#rfc1459[noncompliant]",
		},
		{
			channel: "#{[]}",
			folded:  "#{[]}",
		},
		{
			channel: "#FOO",
			folded:  "#foo",
		},
		{
			channel: "#bang!",
			folded:  "#bang!",
		},
		{
			channel: "#",
			folded:  "#",
		},
		{
			channel: "##",
			folded:  "##",
		},
		{
			channel: "##Ubuntu",
			folded:  "##ubuntu",
		},
		{
			channel:  "#中文频道",
			folded:   "#中文频道",
			nonASCII: true,
		},
		{
			// Hebrew; it's up to the client to display this right-to-left, including the #
			channel:  "#שלום",
			folded:   "#שלום",
			nonASCII: true,
		},
	}

	for _, errCase := range []string{
		"", "#*starpower", "# NASA", "#interro?", "OOF#", "foo", "a b", "#a b",
		// bidi violation mixing latin and hebrew characters:
		"#shalomעליכם",
		"#tab\tcharacter", "#\t", "#carriage\rreturn",
	} {
		testCases = append(testCases, channelTest{channel: errCase, err: true})
	}

	// don't test permissive because it doesn't fail on bidi violations
	casemappings := []i18n.Casemapping{i18n.CasemappingASCII, i18n.CasemappingPRECIS}
	if !i18n.Enabled {
		casemappings = asciiCasemappingOnly // XXX allow testing this package with i18n compiled out
	}

	for _, casemapping := range casemappings {
		globalCasemappingSetting = casemapping

		for i, tt := range testCases {
			t.Run(fmt.Sprintf("case %d: %s", i, tt.channel), func(t *testing.T) {
				res, err := CasefoldChannel(tt.channel)
				errExpected := tt.err || (tt.nonASCII && (casemapping == i18n.CasemappingASCII || casemapping == i18n.CasemappingRFC1459Strict))
				if errExpected && err == nil {
					t.Errorf("expected error when casefolding [%s] under casemapping %d, but did not receive one", tt.channel, casemapping)
					return
				}
				if !errExpected && err != nil {
					t.Errorf("unexpected error while casefolding [%s] under casemapping %d: %s", tt.channel, casemapping, err.Error())
					return
				}
				if !errExpected && tt.folded != res {
					t.Errorf("expected [%v] to be [%v] under casemapping %d", res, tt.folded, casemapping)
				}
			})
		}
	}
}

func TestCasefoldNameAllCasemappings(t *testing.T) {
	oldGlobalCasemapping := globalCasemappingSetting
	t.Cleanup(func() {
		globalCasemappingSetting = oldGlobalCasemapping
	})

	type nameTest struct {
		name   string
		folded string
		err    bool
	}
	testCases := []nameTest{
		{
			name:   "foo",
			folded: "foo",
		},
		{
			name:   "FOO",
			folded: "foo",
		},
	}

	for _, errCase := range []string{
		"", "#", "foo,bar", "star*man*junior", "lo7t?", "a b", "#a b",
		"f.l", "excited!nick", "foo@bar", ":trail",
		"~o", "&o", "@o", "%h", "+v", "-m", "\t", "a\tb",
	} {
		testCases = append(testCases, nameTest{name: errCase, err: true})
	}

	casemappings := []i18n.Casemapping{i18n.CasemappingASCII, i18n.CasemappingPRECIS, i18n.CasemappingPermissive, i18n.CasemappingRFC1459Strict}
	if !i18n.Enabled {
		casemappings = asciiCasemappingOnly // XXX allow testing this package with i18n compiled out
	}

	for _, casemapping := range casemappings {
		globalCasemappingSetting = casemapping

		for i, tt := range testCases {
			t.Run(fmt.Sprintf("case %d: %s", i, tt.name), func(t *testing.T) {
				res, err := CasefoldName(tt.name)
				if tt.err && err == nil {
					t.Errorf("expected error when casefolding [%s], but did not receive one", tt.name)
					return
				}
				if !tt.err && err != nil {
					t.Errorf("unexpected error while casefolding [%s]: %s", tt.name, err.Error())
					return
				}
				if tt.folded != res {
					t.Errorf("expected [%v] to be [%v]", res, tt.folded)
				}
			})
		}
	}
}

func TestIsIdent(t *testing.T) {
	assertIdent := func(str string, expected bool) {
		if isIdent(str) != expected {
			t.Errorf("expected [%s] to have identness [%t], but got [%t]", str, expected, !expected)
		}
	}

	assertIdent("warning", true)
	assertIdent("sid3225", true)
	assertIdent("dan.oak25", true)
	assertIdent("dan.oak[25]", true)
	assertIdent("phi@#$%ip", false)
	assertIdent("Νικηφόρος", false)
	assertIdent("-dan56", false)
}

func TestCanonicalizeMaskWildcard(t *testing.T) {
	tester := func(input, expected string, expectedErr error) {
		out, err := CanonicalizeMaskWildcard(input)
		if expectedErr == nil && out != expected {
			t.Errorf("expected %s to canonicalize to %s, instead %s", input, expected, out)
		}
		if err != expectedErr {
			t.Errorf("expected %s to produce error %v, instead %v", input, expectedErr, err)
		}
	}

	tester("shivaram", "shivaram!*@*", nil)
	tester("slingamn!shivaram", "slingamn!shivaram@*", nil)
	tester("hacker@monad.io", "*!hacker@monad.io", nil)
	tester("Evan!hacker@monad.io", "evan!hacker@monad.io", nil)
	tester("tkadich*", "tkadich*!*@*", nil)
	tester("SLINGAMN!*@*", "slingamn!*@*", nil)
	tester("slingamn!shivaram*", "slingamn!shivaram*@*", nil)
	tester("slingamn!", "slingamn!*@*", nil)
	tester("shivaram*@good-fortune", "*!shivaram*@good-fortune", nil)
	tester("shivaram*", "shivaram*!*@*", nil)
	tester("Shivaram*", "shivaram*!*@*", nil)
	tester("*SHIVARAM*", "*shivaram*!*@*", nil)
	tester("*SHIVARAM*   ", "*shivaram*!*@*", nil)

	tester(":shivaram", "", errInvalidCharacter)
	tester("shivaram!us er@host", "", errInvalidCharacter)
	tester("shivaram!user@ho st", "", errInvalidCharacter)

	if i18n.Enabled {
		tester("ברוך", "ברוך!*@*", nil)
		tester("РОТАТО!Potato", "ротато!potato@*", nil)
	}
}

func TestAllowedCharactersIRCFormatting(t *testing.T) {
	oldAllowed := globalAllowedCharacters
	t.Cleanup(func() {
		globalAllowedCharacters = oldAllowed
	})

	globalAllowedCharacters = AllowedCharactersConfig{
		IRCFormatting: true,
	}

	testCases := []struct {
		input  string
		folded string
		err    bool
	}{
		{"\x02bold\x02", "bold", false},
		{"\x0304,01red\x0f", "red", false},
		{"\x1ditalic\x1d", "italic", false},
		{"\x1funderline\x1f", "underline", false},
		{"\x16reverse\x16", "reverse", false},
		{"\x11monospace\x11", "monospace", false},
		{"\x1estrike\x1e", "strike", false},
		{"\x02\x0304Mixed\x0f\x02", "mixed", false},
		// only formatting codes, no text -> empty string error
		{"\x02\x02", "", true},
		{"\x0304\x0f", "", true},
		// disallowed control characters
		{"\x07bell", "", true},
		{"\x1bescape", "", true},
		{"tab\tcharacter", "", true},
		{"null\x00byte", "", true},
	}

	for _, tt := range testCases {
		res, err := CasefoldName(tt.input)
		if tt.err && err == nil {
			t.Errorf("expected error for [%q], got nil", tt.input)
		} else if !tt.err && err != nil {
			t.Errorf("unexpected error for [%q]: %v", tt.input, err)
		} else if !tt.err && res != tt.folded {
			t.Errorf("expected [%q] to fold to [%q], got [%q]", tt.input, tt.folded, res)
		}
	}
}

func TestAllowedCharactersPrintableGlyphs(t *testing.T) {
	if !i18n.Enabled {
		t.Skip("i18n not enabled")
	}

	oldAllowed := globalAllowedCharacters
	t.Cleanup(func() {
		globalAllowedCharacters = oldAllowed
	})

	globalAllowedCharacters = AllowedCharactersConfig{
		PrintableGlyphs: true,
	}

	testCases := []struct {
		input  string
		folded string
		err    bool
	}{
		// Block elements
		{"█Block█", "█block█", false},
		{"░Shade░", "░shade░", false},
		// Legacy computing (U+1FB00)
		{"\U0001FB00Legacy\U0001FB00", "\U0001fb00legacy\U0001fb00", false},
		// Legacy computing supplement (U+1CC00)
		{"\U0001CC00Supp\U0001CC00", "\U0001cc00supp\U0001cc00", false},
		// Emojis & Symbols
		{"👾gamer👾", "👾gamer👾", false},
		{"🔥Fire🔥", "🔥fire🔥", false},
		// Combining marks
		{"e\u0301clair", "éclair", false},
	}

	for _, tt := range testCases {
		res, err := CasefoldName(tt.input)
		if tt.err && err == nil {
			t.Errorf("expected error for [%q], got nil", tt.input)
		} else if !tt.err && err != nil {
			t.Errorf("unexpected error for [%q]: %v", tt.input, err)
		} else if !tt.err && res != tt.folded {
			t.Errorf("expected [%q] to fold to [%q], got [%q]", tt.input, tt.folded, res)
		}
	}
}
