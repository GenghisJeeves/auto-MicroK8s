/*!
This code is © Copyright Stephen C. Phillips, 2019.
Email: steve@scphillips.com
*/
/*
Licensed under the EUPL, Version 1.2 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence");
You may not use this work except in compliance with the Licence.
You may obtain a copy of the Licence at: https://joinup.ec.europa.eu/community/eupl/
Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the Licence for the specific language governing permissions and limitations under the Licence.
*/

import MorseDecoder from './morse-pro-decoder';

/**
 * Class to convert from timings to Morse code. Uses "international" dictionary. Adapts to changing speed.
 *
 * @example
 * var messageCallback = function(data) {
 *     console.log(data);
 * };
 * var speedCallback = function(s) {
 *     console.log('Speed is now: ' + s.wpm + ' WPM');
 * };
 * var decoder = new MorseAdaptiveDecoder({messageCallback, speedCallback});
 * var t;
 * while (decoder_is_operating) {
 *     // get some ms timing "t" from a sensor, make it +ve for noise and -ve for silence
 *     decoder.addTiming(t);
 * }
 * decoder.flush();  // make sure all the data is pushed through the decoder
 */
export default class MorseAdaptiveDecoder extends MorseDecoder {
    /**
     * 
     * @param {Object} params - dictionary of optional parameters.
     * @param {string} [params.dictionary='international'] - optional dictionary to use. Must have same timing as 'international'.
     * @param {string[]} params.dictionaryOptions - optional additional dictionaries such as 'prosigns'.
     * @param {number} params.wpm - speed in words per minute using "PARIS " as the standard word.
     * @param {number} params.fwpm - farnsworth speed.
     * @param {function()} params.messageCallback - Callback executed with {message: string, timings: number[], morse: string} when decoder buffer is flushed (every character).
     * @param {function()} params.speedCallback - Callback executed with {wpm: number, fwpm: number} if the wpm or fwpm speed changes. The speed in this class doesn't change by itself, but e.g. the fwpm can change if wpm is changed. Returned dictionary has keys 'fwpm' and 'wpm'.
     * @param {number} [bufferSize=30] - Size of the buffer to average over
     */
    constructor({dictionary='international', dictionaryOptions, wpm, fwpm, messageCallback, speedCallback, bufferSize=30} = {}) {
        super({dictionary, dictionaryOptions, wpm, fwpm, messageCallback, speedCallback});
        this.bufferSize = bufferSize;
        this.ditLengths = [];
        this.fditLengths = [];
        // fill the buffers with undefined so as to weight the first reading the same as later ones
        this.ditLengths[bufferSize] = undefined;
        this.fditLengths[bufferSize] = undefined;
        this.lockSpeed = false;
    }

    /**
     * @access private
     */
    _addDecode(duration, character) {
        super._addDecode(duration, character);

        // adapt!
        var dit;
        var fdit;

        switch (character) {
            case '.':
                dit = duration;
                break;
            case '-':
                dit = duration / 3;
                break;
            case '':
                dit = duration;
                break;
            case ' ':
                fdit = duration / 3;
                break;
            // enable this if the decoder can be made to ignore extra long pauses
            // case '/':
            //     fdit = duration / 7;
            //     break;
        }
        this.ditLengths.push(dit);  // put new ones on the end
        this.fditLengths.push(fdit);
        this.ditLengths = this.ditLengths.slice(-this.bufferSize);
        this.fditLengths = this.fditLengths.slice(-this.bufferSize);

        if (this.lockSpeed) { return; }

        var sum = 0;
        var denom = 0;
        var fSum = 0;
        var fDenom = 0;
        var weight;

        for (var i = 0; i < this.bufferSize; i++) {
            weight = i + 1;  // linear weighting
            if (this.ditLengths[i] !== undefined) {
                sum += this.ditLengths[i] * weight;
                denom += weight;
            }
            if (this.fditLengths[i] !== undefined) {
                fSum += this.fditLengths[i] * weight;
                fDenom += weight;
            }
        }

        if (fDenom) {
            this.fditLen = fSum / fDenom;
        }
        if (denom) {
            this.ditLen = sum / denom;
        }

        this.speedCallback({wpm: this.wpm, fwpm: this.fwpm});
    }
}
