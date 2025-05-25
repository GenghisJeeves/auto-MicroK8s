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
 * Web browser sound player for older browsers, using XAudioJS by Grant Galitz (https://github.com/taisel/XAudioJS).
 *
 * @example
 * import MorseCWWave from 'morse-pro-cw-wave';
 * import MorsePlayerXAS from 'morse-pro-player-xas';
 * // make sure XAudioJS is loaded
 * var morseCWWave = new MorseCWWave();
 * morseCWWave.translate("abc");
 * var morsePlayerXAS = new MorsePlayerXAS(XAudioServer);
 * morsePlayerXAS.load(morseCWWave);
 * morsePlayerXAS.playFromStart();
 */
export default class MorsePlayerXAS {
    /**
     * @param {Object} xaudioServerClass - the XAudioServer class
     */
    constructor({XAudioServerClass, morseCWWave, startPadding=0, endPadding=1000, volume=1} = {}) {
        this.XAudioServerClass = XAudioServerClass;
        this.morseCWWave = morseCWWave;
        this.startPadding = startPadding;
        this.endPadding = endPadding;
        this.volume = volume;

        this._isPlaying = false;
        this.samplePos = undefined;
        this.noAudio = false;
        this.audioServer = undefined;
        this.sampleRate = 8000;
        this.sample = undefined;

        var that = this;  // needed so that the 3 closures defined here keep a reference to this object

        // XAudioJS callback to get more samples for buffer
        this.audioGenerator = function(samplesToGenerate) {
            if (samplesToGenerate === 0) {
                return [];
            }
            var ret;
            samplesToGenerate = Math.min(samplesToGenerate, that.sample.length - that.samplePos);
            if (samplesToGenerate > 0) {
                ret = that.sample.slice(that.samplePos, that.samplePos + samplesToGenerate);
                that.samplePos += samplesToGenerate;
                return ret;
            } else {
                that._isPlaying = false;
                return [];
            }
        };

        // XAudioJS failure callback
        this.failureCallback = function() {
            that.noAudio = true;
        };

        setInterval(
            function () {
                // Runs the check to see if we need to give more audio data to the lib
                if (that._isPlaying) {
                    that.audioServer.executeCallback();
                }
            }, 20
        );

        this.load();  // create an xAudioServer so that we know if it works at all and what type it is
    }

    /**
     * Set the volume for the player
     * @param {number} v - the volume, clamped to [0,1]
     */
    set volume(v) {
        this._volume = Math.min(Math.max(v, 0), 1);
        if (this._volume === 0) {
            this._gain = 0;  // make sure 0 volume is actually silent
        } else {
            // see https://teropa.info/blog/2016/08/30/amplitude-and-loudness.html
            let dbfs = -60 + this._volume * 60;  // changes [0,1] to [-60,0]
            this._gain = Math.pow(10, dbfs / 20);  // change from decibels to amplitude
        }
    }

    /**
     * @returns {number} the current volume [0,1]
     */
    get volume() {
        return this._volume;
    }

    /**
     * @returns {number} the current gain [0,1]
     */
    get gain() {
        return this._gain;
    }

    stop() {
        this._isPlaying = false;
        this.audioServer.changeVolume(0);
    }

    /**
     * Load timing sequence, replacing any existing sequence.
     * If this.endPadding is non-zero then an appropriate pause is added to the end.
     * Uses the frequency defined in this.cwWave
     * @param {Object} sequence - the sequence to play.
     * @param {number[]} sequence.timings - list of millisecond timings; +ve numbers are beeps, -ve numbers are silence.
     */
    load(sequence={timings:[]}) {
        let timings = sequence.timings;
        // add on silence at start and end
        timings.unshift(-this.startPadding);
        timings.push(-this.endPadding);
        // TODO: pass in frequencies and volumes once CWWave supports them
        this.sample = this.morseCWWave.getSample(timings);
        this.sampleRate = this.morseCWWave.sampleRate;

        console.log("Trying XAudioServer");

        this.audioServer = new this.XAudioServerClass(
            1,                      // number of channels
            this.sampleRate,        // sample rate
            this.sampleRate >> 2,   // buffer low point for underrun callback triggering
            this.sampleRate << 1,   // internal ring buffer size
            this.audioGenerator,    // audio refill callback triggered when samples remaining < buffer low point
            0,                      // volume
            this.failureCallback    // callback triggered when the browser is found to not support any audio API
        );
    }

    playFromStart() {
        this.stop();
        this._isPlaying = true;
        this.samplePos = 0;
        this.audioServer.changeVolume(this._gain);
    }

    hasError() {
        return this.noAudio;
    }

    get isPlaying() {
        return this._isPlaying;
    }

    get audioType() {
        return this.audioServer.audioType;
        // 3: Audio element using media stream worker
        // 2: Flash
        // 1: Web Audio API with webkit and native support
        // 0: Audio element using Mozilla Audio Data API (https://wiki.mozilla.org/Audio_Data_API)
        // -1: no audio support
    }
}
