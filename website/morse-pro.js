/*!
This code is © Copyright Stephen C. Phillips, 2018.
Email: steve@scphillips.com
*/
/*
Licensed under the EUPL, Version 1.2 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence");
You may not use this work except in compliance with the Licence.
You may obtain a copy of the Licence at: https://joinup.ec.europa.eu/community/eupl/
Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the Licence for the specific language governing permissions and limitations under the Licence.
*/

/**
 * Basic methods to translate Morse code.
 */

import { dictionaries } from "./dictionary/index.js";

export default class Morse {
    /**
     *
     * @param {Object} params - dictionary of optional parameters.
     * @param {String} [params.dictionary='international'] - which dictionary to use, e.g. 'international' or 'american'. Can optionally take a list of dictionary strings.
     * @param {String[]} [params.dictionaryOptions=[]] - optional additional dictionaries such as 'prosigns'. Will look these up in the merged dictionary formed of the list of dictionaries.
     */
    constructor({dictionary='international', dictionaryOptions=[]} = {}) {
        if (typeof dictionary === 'string') {
            dictionary = [dictionary];
        }
        this.setDictionariesAndOptions(dictionary, dictionaryOptions);
    }

    setDictionariesAndOptions(dictList, optionList) {
        this.dictionaries = dictList;
        this.options = optionList;
        this._loadDictionaries();
    }

    /**
     * Set the list of dictionaries to use.
     * @param {List} dictList - list of dictionary names
     */
    setDictionaries(dictList) {
        this.dictionaries = dictList;
        this._loadDictionaries();
    }

    /**
     * Set the list of dictionary options to use.
     * @param {List} optionList - list of dictionary option names. Looked up in merged dictionary
     */
    setOptions(optionList) {
        this.options = optionList;
        this._loadDictionaries()
    }

    _loadDictionaries() {
        // Clear any existing mappings:
        this.text2morseD = {};
        this.morse2textD = {};
        // Set up sensible default:
        this._addDictionary({
            letter:{'':''},
            letterMatch:/^./
        });
        // Load in all dictionaries:
        for (let d of this.dictionaries) {
            if (d in dictionaries) {
                let dict = dictionaries[d]  // switch to the imported dict
                this._addDictionary(dict);
            } else {
                throw `No dictionary called '${d}'`;
            }
        }
        // Overlay any options:
        for (let optName of this.options) {
            if (this.dictionary.options[optName] !== undefined) {
                this._addDictionary(this.dictionary.options[optName])
            } else {
                throw `No option '${optName}' in '${this.dictionary.id}'`;
            }
        }
    }

    /**
     * Load in a dictionary.
     * Dictionary needs 'letter' and (optional) 'letterMatch' keys.
     * @param {Object} dict
     */
    _addDictionary(dict) {
        this.dictionary = {...this.dictionary, ...dict};  // overwrite any existing keys with the new dict

        let letters = dict.letter;
        for (let letter in letters) {
            // overwrite any existing letter keys
            this.text2morseD[letter] = letters[letter];
            this.morse2textD[letters[letter]] = letter;
        }
    }

    /**
     * General method for converting a set of tokens to a displayable string
     * @param {Array} tokens - list of lists of tokens to form into String
     * @param {String} charSpace - String to use to separate characters
     * @param {String} wordSpace - String to use to separate words
     * @param {Map} map - Map to replace tokens with alternatives, e.g. for display escaping {'>', '&gt;'}
     * @param {Array} errors - list if lists of Booleans indicating if there is an error in the tokens parameter
     * @param {String} errorPrefix - used to prefix any token that is an error
     * @param {String} errorSuffix - used to suffix any token that is an error
     * @returns a String of the tokens
     */
    display(tokens, charSpace, wordSpace, map={}, errors=undefined, errorPrefix='', errorSuffix='') {
        for (let k in map) {
            tokens = tokens.map(word => word.map(char => char.replace(new RegExp(k, 'g'), map[k])));
        }
        if (errors !== undefined) {
            for (let i = 0; i < tokens.length; i++) {
                for (let j = 0; j < tokens[i].length; j++) {
                    if (errors[i][j]) {
                        tokens[i][j] = errorPrefix + tokens[i][j] + errorSuffix;
                    }
                }
            }
        }
        let words = tokens.map(word => word.join(charSpace));
        return words.join(wordSpace);
    }

    /**
     * Tidies text (upper case, trim, squash multiple spaces)
     * @param {String} text - the text to tidy
     * @returns the tidied text
     */
    tidyText(text) {
        text = text.trim();
        text = text.replace(/\s+/g, ' ');
        return text;
    }

    /**
     * Splits text into words and letters
     * @param {String} text - the text to tokenise
     * @returns a list of lists, e.g. [['o', 'n', 'e'], ['t', 'w', 'o']]
     */
    tokeniseRawText(text) {
        let tokens = []
        let words = text.split(' ');
        for (let word of words) {
            let letters = [];
            while (word.length) {
                let letter = word.match(this.dictionary.letterMatch)[0];
                word = word.substr(letter.length);
                letters.push(letter);
            }
            tokens.push(letters);
        }
        return tokens;
    }

    /**
     * Tidies and then tokenises text
     * @param {String} text - the text to tokenise
     * @returns - the tidied, tokenised text
     */
    tokeniseText(text) {
        return this.tokeniseRawText(this.tidyText(text));
    }

    /**
     * Convert from text tokens to displayable String
     * @param {Array} textTokens - list of lists representing the words and characters
     * @param {Map} escapeMap - Map to replace tokens with alternatives, e.g. for display escaping {'>', '&gt;'}
     * @returns a String, joining the characters together, separating the words with a space
     */
    displayText(textTokens, escapeMap) {
        return this.display(textTokens, '', ' ', escapeMap)
    }

    displayTextErrors(textTokens, escapeMap, errorTokens, prefix, suffix) {
        return this.display(textTokens, '', ' ', escapeMap, errorTokens, prefix, suffix);
    }

    /**
     *
     * @param {Array} textTokens - list of lists of text tokens
     * @returns Map - text: text tokens, morse: morse tokens, error: error tokens, hasError Boolean
     */
    textTokens2morse(textTokens) {
        let translation = this._input2output(textTokens, this.text2morseD);
        return {
            text: textTokens,
            morse: translation.output,
            error: translation.error,
            hasError: translation.hasError
        }
    }

    text2morse(text) {
        let textTokens = this.tokeniseText(text);
        return this.textTokens2morse(textTokens);
    }

    tokeniseMorse(morse) {
        return this.dictionary.tokeniseMorse(morse);
    }

    displayMorse(morseTokens) {
        return this.display(morseTokens,
            this.dictionary.display.join.charSpace, this.dictionary.display.join.wordSpace, this.dictionary.display.morse);
    }

    displayMorseErrors(morseTokens, errorTokens, prefix, suffix) {
        return this.display(morseTokens,
            this.dictionary.display.join.charSpace, this.dictionary.display.join.wordSpace, this.dictionary.display.morse,
            errorTokens, prefix, suffix);
    }

    morseTokens2text(morseTokens) {
        let translation = this._input2output(morseTokens, this.morse2textD);
        return {
            morse: morseTokens,
            text: translation.output,
            error: translation.error,
            hasError: translation.hasError
        }
    }

    morse2text(morse) {
        let morseTokens = this.tokeniseMorse(morse);
        return this.morseTokens2text(morseTokens);
    }

    looksLikeMorse(input) {
        return input.match(this.dictionary.morseMatch) !== null;
    }

    _input2output(tokens, dict) {
        let ret = {
            output: [],
            error: [],
            hasError: false
        }
        for (let letters of tokens) {
            let chars = [];
            let errors = [];
            for (let letter of letters) {
                let char = '';
                let error = false;
                // These tests are a little complex because e.g. the american dictionary uses "s" and "S" in the Morse.
                // You therefore have to test without uppercasing.
                // The uppercase test is useful though (so added here) so that the case of the input itself doesn't have to be changed.
                // That's helpful e.g. when someone enters text in the translator that needs cleaning up: the case can be maintained.
                if (letter in dict) {
                    char = dict[letter];
                } else if (letter.toUpperCase() in dict) {
                    char = dict[letter.toUpperCase()];
                } else {
                    error = true;
                }
                chars.push(char);
                errors.push(error);
                ret.hasError = ret.hasError || error;
            }
            ret.output.push(chars);
            ret.error.push(errors);
        }
        return ret;
    }

    text2morseClean(text) {
        let d = this.text2morse(text);
        d.text = d.text.map((word, i) => word.filter((char, j) => !d.error[i][j]));
        d.morse = d.morse.map((word, i) => word.filter((char, j) => !d.error[i][j]));
        d.error = d.error.map(word => word.filter(error => !error));
        d.hasError = false;
        return d;
    }
}

