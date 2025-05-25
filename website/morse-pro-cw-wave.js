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

import MorseCW from './morse-pro-cw';

/**
 * Class to create sine-wave samples of standard CW Morse.
 *
 * @example
 * import MorseCWWave from 'morse-pro-cw-wave';
 * var morseCW = new MorseCW();
 * var tokens = morseCW.text2morse("abc");
 * var timings = morseCW.morseTokens2timing(tokens);
 * var sample = morseCWWave.getSample(timings);
 */
export default class MorseCWWave extends MorseCW {
    /**
     * @param {Object} params - dictionary of optional parameters.
     * @param {string} params.dictionary - which dictionary to use, e.g. 'international' or 'american'.
     * @param {string[]} params.dictionaryOptions - optional additional dictionaries such as 'prosigns'.
     * @param {number} params.wpm - speed in words per minute using "PARIS " as the standard word.
     * @param {number} params.fwpm - farnsworth speed.
     * @param {number} [params.frequency=550] - frequency of wave in Hz
     * @param {number} [params.sampleRate=8000] - sample rate for the waveform in Hz
     */
    constructor({dictionary, dictionaryOptions, wpm, fwpm, frequency=550, sampleRate=8000} = {}) {
        super({dictionary, dictionaryOptions, wpm, fwpm});
        // TODO: make this.frequency a fallback and replace with arrays of freq and volume to go with timings array when making a sample
        /** @type {number} */
        this.frequency = frequency;  // frequency of wave in Hz
        /** @type {number} */
        this.sampleRate = sampleRate;  // sample rate for the waveform in Hz
    }

    /**
     * Get a sample waveform, not using Web Audio API (synchronous).
     * @param {number[]} timings - millisecond timings, +ve numbers representing sound, -ve for no sound (+ve/-ve can be in any order)
    // TODO * @param {number[]} frequencies - frequencies of elements in Hz.
    // TODO * @param {number[]} volumes - volumes of elements in Hz.
    // TODO: remove endpadding?
     * @param {number} [endPadding=0] - how much silence in ms to add to the end of the waveform.
     * @return {number[]} an array of floats in range [-1, 1] representing the wave-form.
     */
    getSample(timings, endPadding = 0) {
        var sample = [];
        if (timings.length === 0) {
            return [];
        }
        // add minimum of 5ms silence to the end to ensure the filtered signal can finish cleanly
        if (timings[timings.length - 1] > 0) {
            timings.push(-Math.max(5, endPadding));
        } else {
            timings[timings.length - 1] = -Math.max(5, endPadding, -timings[timings.length - 1]);
        }

        /*
            Compute lowpass biquad filter coefficients using method from Chromium
        */

        // set lowpass frequency cutoff to 1.5 x wave frequency
        var lowpassFreq = (this.frequency * 1.5) / this.sampleRate;
        var q = Math.SQRT1_2;
      
        var sin = Math.sin(2 * Math.PI * lowpassFreq);
        var cos = Math.cos(2 * Math.PI * lowpassFreq);
        var alpha = sin / (2 * Math.pow(10, q / 20));
      
        var a0 =  1 + alpha;

        var b0 = ((1 - cos) * 0.5) / a0;
        var b1 = (1 - cos) / a0;
        var b2 = ((1 - cos) * 0.5) / a0;
        var a1 = (-2 * cos) / a0;
        var a2 = (1 - alpha) / a0;

        /*
            Compute filtered signal
        */

        var step = Math.PI * 2 * this.frequency / this.sampleRate;
        var on, duration;
        var x0, x1 = 0, x2 = 0;
        var y0, y1 = 0, y2 = 0;
        var gain = 0.813;  // empirically, the lowpass filter outputs waveform of magnitude 1.23, so need to scale it down to avoid clipping
        for (var t = 0; t < timings.length; t += 1) {
            duration = this.sampleRate * Math.abs(timings[t]) / 1000;
            on = timings[t] > 0 ? 1 : 0;
            for (var i = 0; i < duration; i += 1) {
                x0 = on * Math.sin(i * step);  // the input signal
                y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
                sample.push(y0 * gain);
                x2 = x1;
                x1 = x0;
                y2 = y1;
                y1 = y0;
            }
        }
        return sample;
    }

    /**
     * Get a sample waveform using Web Audio API (asynchronous).
     * @param {number[]} timings - millisecond timings, +ve numbers representing sound, -ve for no sound (+ve/-ve can be in any order)
    // TODO * @param {number[]} frequencies - frequencies of elements in Hz.
    // TODO * @param {number[]} volumes - volumes of elements in Hz.
    // TODO: remove endpadding?
     * @param {number} [endPadding=0] - how much silence in ms to add to the end of the waveform.
     * @return {Promise(number[])} a Promise resolving to an array of floats in range [-1, 1] representing the wave-form.
     */
    getWAASample(timings, endPadding = 0) {
        // add minimum of 5ms silence to the end to ensure the filtered signal can finish cleanly
        if (timings[timings.length - 1] > 0) {
            timings.push(-Math.max(5, endPadding));
        } else {
            timings[timings.length - 1] = -Math.max(5, endPadding, -timings[timings.length - 1]);
        }
        var offlineAudioContextClass = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (offlineAudioContextClass === undefined) {
            throw new Error("No OfflineAudioContext class defined");
        }
        // buffer length is the Morse duration + 5ms to let the lowpass filter end cleanly
        var offlineCtx = new offlineAudioContextClass(1, this.sampleRate * (this.getDuration() + endPadding) / 1000, this.sampleRate);
        var gainNode = offlineCtx.createGain();
        // empirically, the lowpass filter outputs waveform of magnitude 1.23, so need to scale it down to avoid clipping
        gainNode.gain.setValueAtTime(0.813, 0);
        var lowPassNode = offlineCtx.createBiquadFilter();
        lowPassNode.type = "lowpass";
        lowPassNode.frequency.setValueAtTime(this.frequency * 1.1, 0);  // TODO: remove this magic number and make the filter configurable?
        gainNode.connect(lowPassNode);
        lowPassNode.connect(offlineCtx.destination);
        var t = 0;
        var oscillator;
        var duration;
        for (var i = 0; i < timings.length; i++) {
            duration = Math.abs(timings[i]) / 1000;
            if (timings[i] > 0) {  // -ve timings are silence
                oscillator = offlineCtx.createOscillator();
                oscillator.type = 'sine';
                oscillator.frequency.setValueAtTime(this.frequency, t);
                oscillator.start(t);
                oscillator.stop(t + duration);
                oscillator.connect(gainNode);
            }
            t += duration;
        }
        return offlineCtx.startRendering().then(function(renderedBuffer) {
            return renderedBuffer.getChannelData(0);
        });
    }
}
