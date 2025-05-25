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

import Morse from './morse-pro';

const MS_IN_MINUTE = 60000;  /** number of milliseconds in 1 minute */

/**
 * Class to create the on/off timings needed by e.g. sound generators. Timings are in milliseconds; "off" timings are negative.
 *
 * @example
 * import MorseCW from 'morse-pro-cw';
 * var morseCW = new MorseCW();
 * var tokens = morseCW.text2morse("abc");
 * var timings = morseCW.morseTokens2timing(tokens);
 */
export default class MorseCW extends Morse {
    /**
     * @param {Object} params - dictionary of optional parameters.
     * @param {string} [params.dictionary='international'] - which dictionary to use, e.g. 'international' or 'american'.
     * @param {string[]} [params.dictionaryOptions=[]] - optional additional dictionaries such as 'prosigns'.
     * @param {number} [params.wpm=20] - speed in words per minute using "PARIS " as the standard word.
     * @param {number} [params.fwpm=wpm] - farnsworth speed.
     */
    constructor({dictionary, dictionaryOptions, wpm=20, fwpm=wpm} = {}) {
        super({dictionary, dictionaryOptions});
        /** The element of the dictionary that the ratios are based off */
        this._baseElement = this.dictionary.baseElement;
        /** In initialise the ratios based on the dictionary but enable them to be changed thereafter */
        this.ratios = this.dictionary.ratio;  // actually does a copy from the dict so we can reset if needed
        /** Compute ditsInParis and spacesInParis while we have original ratio */
        let parisMorseTokens = this.textTokens2morse(this.tokeniseRawText('PARIS')).morse;
        this._ditsInParis = this.getDuration(this.morseTokens2timing(parisMorseTokens, this.ratios)) + Math.abs(this.ratios.wordSpace);
        this._spacesInParis = Math.abs((4 * this.ratios.charSpace) + this.ratios.wordSpace);
        /** Initialise wpm and fwpm (this potentially changes the ratios) */
        this.setWPM(wpm);
        this.setFWPM(fwpm);
    }

    /** 
     * Set the WPM speed. Ensures that Farnsworth WPM is no faster than WPM.
     * @param {number} wpm
     */
    setWPM(wpm) {
        this._baseLength = undefined;
        this._ratios = undefined;
        this._lengths = undefined;

        wpm = Math.max(1, wpm || 1);
        this._wpm = wpm;
        this._fwpm = Math.min(this._wpm, this._fwpm);

        let tmp = this.ratios;
        tmp = this.baseLength;
        return wpm;
    }

    /** @type {number} */
    get wpm() {
        return this._wpm;
    }

    testWPMmatchesRatio() {
        return this.ratios['-'] == this.dictionary.ratio['-'] && this.ratios[' '] == this.dictionary.ratio[' '];
    }

    /**
     * Set the Farnsworth WPM speed. Ensures that WPM is no slower than Farnsworth WPM.
     * @param {number} fwpm
     */
    setFWPM(fwpm) {
        fwpm = Math.max(1, fwpm || 1);
        this._fwpm = fwpm;
        this.setWPM(Math.max(this._wpm, this._fwpm))
        
        return fwpm;
    }

    /** @type {number} */
    get fwpm() {
        return this._fwpm;
    }

    testFWPMmatchesRatio() {
        // need to test approximately here otherwise with the rounding errors introduced in the web page input it would never return true
        return Math.abs((this.ratios['wordSpace'] / this.dictionary.ratio['wordSpace']) / (this.ratios['charSpace'] / this.dictionary.ratio['charSpace']) - 1) < 0.001;
    }

    /** @type {number[]} */
    get ratios() {
        if (this._ratios === undefined) {
            this._ratios = {};
            Object.assign(this._ratios, this.dictionary.ratio);
            let farnsworthRatio = this.farnsworthRatio;
            this._ratios['charSpace'] *= farnsworthRatio;
            this._ratios['wordSpace'] *= farnsworthRatio;
        }
        return this._ratios;
    }

    /**
     * Set the ratio of each element and normalise to the base element/
     * For the space elements, the ratio is negative.
     * @param {Map} r - a Map from element to ratio (as defined in the 'ratio' element of a dictionary)
     */
    set ratios(r) {
        this._wpm = undefined;
        this._fwpm = undefined;
        this._lengths = undefined;

        this._ratios = {};
        Object.assign(this._ratios, r);
        for (let element in this._ratios) {
            this._ratios[element] /= this._ratios[this._baseElement];
        }
    }

    setRatio(element, ratio) {
        let tmp = this.ratios;
        this._ratios[element] = ratio;
        this._lengths = undefined;

        if (this.testWPMmatchesRatio()) {
            this._setWPMfromBaseLength();
            if (this.testFWPMmatchesRatio()) {
                this._setFWPMfromRatio();
            } else {
                this._fwpm = undefined;
            }    
        } else {
            this._wpm = undefined;
            this._fwpm = undefined;
        }
    }

    /**
     * Return an array of millisecond timings.
     * With the Farnsworth method, the morse characters are played at one
     * speed and the spaces between characters at a slower speed.
     * @param {Array} morseTokens - array of morse tokens corresponding to the ratio element of the dictionary used, e.g. [['..', '.-'], ['--', '...']]
     * @param {Object} [lengths=this.lengths] - dictionary mapping element to duration with negative duration for spaces
     * @return {number[]}
     */
    morseTokens2timing(morseTokens, lengths=this.lengths) {
        let timings = [];
        for (let word of morseTokens) {
            for (let char of word) {
                timings = timings.concat(char.split('').map(symbol => lengths[symbol]));
                timings = timings.concat(lengths.charSpace);
            }
            timings.pop()
            timings = timings.concat(lengths.wordSpace);
        }
        timings.pop();
        return timings;
    }

    /**
     * Add up all the millisecond timings in a list
     * @param {Array} timings - list of millisecond timings (-ve for spaces)
     */
    getDuration(timings) {
        return timings.reduce(
            (accumulator, currentValue) => accumulator + Math.abs(currentValue),
            0
        );
    }

    /**
     * Get the Farnsworth dit length to dit length ratio
     * @return {number}
     */
    get farnsworthRatio() {
        // Compute fditlen / ditlen
        // This should be >1 and it is what you need to multiply the standard charSpace and wordSpace ratios by to get the adjusted farnsworth ratios
        // "PARIS " is 31 units for the characters and 19 units for the inter-character spaces and inter-word space
        // One unit takes 1 * 60 / (50 * wpm)
        // The 31 units should take 31 * 60 / (50 * wpm) seconds at wpm
        // "PARIS " should take 50 * 60 / (50 * fwpm) to transmit at fwpm, or 60 / fwpm  seconds at fwpm
        // Keeping the time for the characters constant,
        // The spaces need to take: (60 / fwpm) - [31 * 60 / (50 * wpm)] seconds in total
        // The spaces are 4 inter-character spaces of 3 units and 1 inter-word space of 7 units. Their ratio must be maintained.
        // A space unit is: [(60 / fwpm) - [31 * 60 / (50 * wpm)]] / 19 seconds
        // Comparing that to 60 / (50 * wpm) gives a ratio of (50.wpm - 31.fwpm) / 19.fwpm
        return (this._ditsInParis * this._wpm - (this._ditsInParis - this._spacesInParis) * this._fwpm) / (this._spacesInParis * this._fwpm);
    }

    /**
     * Force the WPM to match the base length without changing anything else
     */
    _setWPMfromBaseLength() {
        this._wpm = (MS_IN_MINUTE / this._ditsInParis) / this._baseLength;
    }

    /**
     * Set the WPM given dit length in ms
     * @param {number} ditLen
     */
    setWPMfromDitLen(ditLen) {
        this.setWPM((MS_IN_MINUTE / this._ditsInParis) / ditLen);
    }

    /** 
     * Force the FWPM to match the fditlen/ditlen ratio without changing anything else
     */
    _setFWPMfromRatio() {
        let ratio = Math.abs((this.lengths['charSpace'] / 3) / this.lengths['.']);
        this._fwpm = this._ditsInParis * this._wpm / (this._spacesInParis * ratio + (this._ditsInParis - this._spacesInParis));
    }

    /** 
     * Set the Farnsworth WPM given ratio of fditlength / ditlength
     * @param {number} ratio
     */
     setFWPMfromRatio(ratio) {
        ratio = Math.max(Math.abs(ratio), 1);  // take abs just in case someone passes in something -ve
        this.setFWPM(this._ditsInParis * this._wpm / (this._spacesInParis * ratio + (this._ditsInParis - this._spacesInParis)));
    }

    /**
     * Get the length of the base element (i.e. a dit) in milliseconds
     * @return {number}
     */
    get baseLength() {
        this._baseLength = this._baseLength || (MS_IN_MINUTE / this._ditsInParis) / this._wpm;
        return this._baseLength;
    }

    /**
     * Calculate and return the millisecond duration of each element, using negative durations for spaces.
     * @returns Map
     */
    get lengths() {
        if (this._lengths === undefined) {
            this._lengths = {};
            this._maxLength = 0;
            Object.assign(this._lengths, this.ratios);
            for (let element in this._lengths) {
                this._lengths[element] *= this._baseLength;
                this._maxLength = Math.max(this._maxLength, this._lengths[element]);
            }
        }
        return this._lengths;  // this is just a cache for speed, the ratios define the lengths
    }

    /**
     * Return the length of the longest beep in milliseconds.
     * @returns {number}
     */
    get maxLength() {
        if (this._lengths === undefined) {
            let tmp = this.lengths;
        }
        return this._maxLength;
    }

    setLength(element, length) {
        if (element == this._baseElement) {
            this._lengths = undefined;
            this._wpm = undefined;
            this._fwpm = undefined;

            this._baseLength = length;
        }
        this.setRatio(element, length / this._baseLength);
    }

    /** 
     * Get the absolute duration of the space between words in ms.
     * @type {number}
     */
    get wordSpace() {
        return Math.abs(this.lengths.wordSpace);
    }
}
