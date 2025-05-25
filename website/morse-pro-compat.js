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

import Morse from "./morse-pro.js";

/**
 * Translate text to morse in '..- .. / --' form.
 * If something in the text is untranslatable then it is surrounded by hash-signs ('#') and a hash is placed in the morse.
 * @param {string} text - alphanumeric message
 * @param {boolean} useProsigns - true if prosigns are to be used (default is true)
 * @return {{message: string, morse: string, hasError: boolean}}
 * @deprecated
 */
export function text2morse(text, useProsigns = true) {
    let ret = {
        morse: "",
        message: "",
        hasError: false
    };
    if (text === "") {
        return ret;
    }

    let morse = new Morse({dictionary: 'international', useProsigns});
    let textTokens = morse.tokeniseText(text);
    let tme = morse.textTokens2morse(textTokens);

    for (let w = 0; w < tme.text.length; w++) {
        for (let c = 0; c < tme.text[w].length; c++) {
            let t = tme.text[w][c];
            let m = tme.morse[w][c];
            if (tme.error[w][c]) {
                ret.message += "#" + t + "#";
                ret.morse += "# ";
            } else {
                ret.message += t;
                ret.morse += m.replace(/ /g, '') + " ";
            }
        }
        ret.message += ' ';
        ret.morse += '/ ';
    }
    ret.message = ret.message.slice(0, ret.message.length - 1);
    ret.morse = ret.morse.slice(0, ret.morse.length - 3);
    ret.hasError = tme.hasError;
    return ret;
}

/**
 * Translate text to morse in 'Di-di-dah dah' form.
 * @param {string} text - alphanumeric message
 * @param {boolean} useProsigns - true if prosigns are to be used (default is true)
 * @return {string}
 * @deprecated
 */
export function text2ditdah(text, useProsigns) {
    // TODO: deal with errors in the translation
    var ditdah = text2morse(text, useProsigns).morse + ' '; // get the dots and dashes
    ditdah = ditdah.replace(/\./g, 'di~').replace(/\-/g, 'dah~'); // do the basic job
    ditdah = ditdah.replace(/~/g, '-'); // replace placeholder with dash
    ditdah = ditdah.replace(/\- /g, ' '); // remove trailing dashes
    ditdah = ditdah.replace(/di /g, 'dit '); // use 'dit' at end of letter
    ditdah = ditdah.replace(/ \/ /g, ', '); // do punctuation
    ditdah = ditdah.replace(/^d/, 'D'); // do capitalisation
    ditdah = ditdah.replace(/ $/, ''); // remove the space we added
    ditdah = ditdah.replace(/([th])$/, '$1.'); // add full-stop if there is anything there
    return ditdah;
}

/**
 * Canonicalise morse text.
 * Canonical form matches [.-/ ]*, has single spaces between characters, has words separated by ' / ', and has no spaces at the start or end.
 * A single '/' may be returned by this function.
 * @param {string} morse - Morse code matching [.-_/| ]*
 * @return {string} Morse code in canonical form matching [.-/ ]*
 * @deprecated
 */
export function tidyMorse(morse) {
    let morseInstance = new Morse();
    return morseInstance.displayMorse(morseInstance.tokeniseMorse(morse));
}

/**
 * Translate morse to text. Canonicalise the morse first.
 * If something in the morse is untranslatable then it is surrounded by hash-signs ('#') and a hash is placed in the text.
 * @param {string} morse - morse message using [.-_/| ] characters
 * @param {boolean} useProsigns - true if prosigns are to be used (default is true)
 * @return {{message: string, morse: string, hasError: boolean}}
 * @deprecated
 */
export function morse2text(morse, useProsigns = true) {
    let ret = {
        morse: "",
        message: "",
        hasError: false
    };
    if (morse === "") {
        return ret;
    }

    let morseInstance = new Morse({dictionary: 'international', useProsigns});
    let morseTokens = morseInstance.tokeniseMorse(morse);
    let tme = morseInstance.morseTokens2text(morseTokens);
    // console.log(tme);

    for (let w = 0; w < tme.morse.length; w++) {
        for (let c = 0; c < tme.morse[w].length; c++) {
            let t = tme.text[w][c];
            let m = tme.morse[w][c].replace(/ /g, '');
            if (tme.error[w][c]) {
                ret.message += "#";
                ret.morse += "#" + m + "# ";
            } else {
                ret.message += t;
                ret.morse += m + " ";
            }
        }
        ret.message += ' ';
        ret.morse += '/ ';
    }
    ret.message = ret.message.slice(0, ret.message.length - 1);
    ret.morse = ret.morse.slice(0, ret.morse.length - 2).trim();
    ret.hasError = tme.hasError;
    return ret;
}

/**
 * Determine whether a string is most likely morse code.
 * @param {string} input - the text
 * @return {boolean} - true if the string only has Morse characters in after executing tidyMorse
 * @deprecated
 */
export function looksLikeMorse(input) {
    let morse = new Morse({dictionary: 'international'});
    return morse.looksLikeMorse(input);
}
