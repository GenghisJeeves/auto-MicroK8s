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

import MorsePlayerWAA from './morse-pro-player-waa';
import morseAudioContext from './morse-pro-audiocontext';

/**
 * Web browser sound player using Web Audio API.
 * Extends MorsePlayerWAA to provide callbacks when the sound goes on or off.
 * Can be used to turn a light on or off in time with the Morse sound.
 * The callbacks have an error of +/- 2.6ms
 *
 * @example
 * import MorseCW from 'morse-pro-cw';
 * import MorsePlayerWAALight from 'morse-pro-player-waa-light';
 * var morseCW = new MorseCW();
 * var tokens = morseCW.text2morse("abc");
 * var timings = morseCW.morseTokens2timing(tokens);
 * var morsePlayerWAALight = new MorsePlayerWAALight();
 * morsePlayerWAALight.soundOnCallback = lightOn;
 * morsePlayerWAALight.soundOffCallback = lightOff;
 * morsePlayerWAALight.soundStoppedCallback = soundStopped;
 * morsePlayerWAALight.muteAudio(true);
 * morsePlayerWAALight.load({timings});
 * morsePlayerWAA.playFromStart();
 */

const SMALL_AMPLITUDE = 0.1;  // below this, we consider the sound to be off

export default class MorsePlayerWAALight extends MorsePlayerWAA {
    /**
     * @param {Object} params - lots of optional parameters.
     * @param {number} params.defaultFrequency - fallback frequency (Hz) to use if the loaded sequence does not define any.
     * @param {number} params.startPadding - number of ms to wait before playing first note of initial sequence.
     * @param {number} params.endPadding - number of ms to wait at the end of a sequence before playing the next one (or looping).
     * @param {number} params.volume - volume of Morse. Takes range [0,1].
     * @param {function()} params.sequenceStartCallback - function to call each time the sequence starts.
     * @param {function()} params.sequenceEndingCallback - function to call when the sequence is nearing the end.
     * @param {function()} params.sequenceEndCallback - function to call when the sequence has ended.
     * @param {function()} params.soundStoppedCallback - function to call when the sequence stops.
     * @param {function()} params.soundOnCallback - function to call when a note starts.
     * @param {function()} params.soundOffCallback - function to call when a note stops.
     * @param {string} params.onSample - URL of the sound file to play at the start of a note.
     * @param {string} params.offSample - URL of the sound file to play at the end of a note.
     * @param {string} params.playMode - play mode, either "sine" or "sample".
     */
    constructor({defaultFrequency, startPadding, endPadding, volume, sequenceStartCallback, sequenceEndingCallback, sequenceEndCallback, soundStoppedCallback, soundOnCallback, soundOffCallback, onSample, offSample, playMode} = {}) {
        super({defaultFrequency, startPadding, endPadding, volume, sequenceStartCallback, sequenceEndingCallback, sequenceEndCallback, soundStoppedCallback, onSample, offSample, playMode});
        if (soundOnCallback !== undefined) this.soundOnCallback = soundOnCallback;
        if (soundOffCallback !== undefined) this.soundOffCallback = soundOffCallback;
        this._wasOn = false;
        this._count = 0;
        if (playMode === 'sample') {
            console.log('WARNING: The light does not yet work when using "sample" play mode');
        }
    }

    /**
     * Set up the audio graph, connecting the splitter node to a JSNode in order to analyse the waveform
     * @access private
     */
    _initialiseAudio() {
        // TODO: have this create its own oscillators so that we can get the light signal when using samples
        // TODO: or just adapt the super class to call soundOn and soundOff callbacks based on the timings - not sure why I didn't do that in the first place? Could be to do with the higher precision of the sound API?!
        super._initialiseAudio();
        if (this.jsNode) {
            // if we have already called this method then must make sure to disconnect the old node graph first
            this.jsNode.disconnect();
        }
        let ac = morseAudioContext.getAudioContext();

        this.muteLightNode = ac.createGain();  // used to temporarily mute the light (e.g. if just sound is needed)

        this.jsNode = ac.createScriptProcessor(256, 1, 1);
        this.jsNode.connect(ac.destination);  // otherwise Chrome ignores it
        this.jsNode.onaudioprocess = this._processSound.bind(this);

        this.splitterNode.connect(this.muteLightNode);
        this.muteLightNode.connect(this.jsNode);

        this.muteLight(false);
    }

    /**
     * @access private
     */
    _processSound(event) {
        var input = event.inputBuffer.getChannelData(0);
        var sum = 0;
        for (var i = 0; i < input.length; i++) {
            sum += Math.abs(input[i]) > SMALL_AMPLITUDE;
        }
        var on = (sum > 128);  // is more than half the buffer non-zero?
        if (on && !this._wasOn) {
            this._on();
        } else if (!on && this._wasOn) {
            this._off();
        }
        this._wasOn = on;
    }

    /**
     * @access private
     */
    _on() {
        this.soundOnCallback();
    }

    /**
     * @access private
     */
    _off() {
        this.soundOffCallback();
    }

    muteLight(mute) {
        let now = morseAudioContext.getAudioContext().currentTime;
        this.muteLightNode.gain.setValueAtTime(mute ? 0 : 1, now);
    }

    /**
     * @returns {number} representing this audio player type: 5
     * @override
     */
    get audioType() {
        return 5;
        // 5: Web Audio API using oscillators and light control
        // 4: Web Audio API using oscillators
        // 3: Audio element using media stream worker (using PCM audio data)
        // 2: Flash (using PCM audio data)
        // 1: Web Audio API with webkit and native support (using PCM audio data)
        // 0: Audio element using Mozilla Audio Data API (https://wiki.mozilla.org/Audio_Data_API) (using PCM audio data)
        // -1: no audio support
    }

    // empty callbacks in case user does not define any
    soundOnCallback() { }
    soundOffCallback() { }
}
