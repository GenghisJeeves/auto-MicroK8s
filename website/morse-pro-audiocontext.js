class MorseAudioContext {
    constructor() {
        this.AudioContext = window.AudioContext || window.webkitAudioContext;
        if (this.AudioContext === undefined) {
            this.hasAudioContext = false;
            console.log("Web Audio API unavailable");
            return;
            // throw (new Error("No AudioContext class defined"));
        }
        this.hasAudioContext = true;
        this.sounds = {};
        this._unlocked = false;
        let ua = navigator.userAgent.toLowerCase();
        this.isIOS = (ua.indexOf("iphone") >= 0 && ua.indexOf("like iphone") < 0 || ua.indexOf("ipad") >= 0 && ua.indexOf("like ipad") < 0 || ua.indexOf("ipod") >= 0 && ua.indexOf("like ipod") < 0);
        // if (this.isIOS) this.playHTMLaudio();
    }

    /**
     * Get an AudioContext. The state of the AudioContext may be "suspended".
     * In Chrome (v83 Windows), Safari (v13.1 Mac Catalina), iOS (v11) you get a running context (and runUnlockedActions executes) upon user interaction.
     * In Edge (v44.18362.449.0 Windows) you get a running AudioContext straight away but the runUnlockedActions executes.
     * In Firefox (v75 Windows) you get a suspended AudioContext but it resumes (and runUnlockedActions executes) after a short while without interaction.
     */
    getAudioContext() {
        // console.log("Getting AC");
        if (this.audioContext !== undefined) {
            if (this.audioContext.state === "running") {
                // console.log("AC is running");
            } else {
                // console.log("AudioContext is suspended");
                this.audioContext.resume().then(() => {this.runUnlockedActions(1)});
            }
        } else {
            console.log("Creating AudioContext");
            this.audioContext = new this.AudioContext();
            this.audioContext.createGain();  // Can help on Safari. Probably not needed but can't hurt
            console.log(`AudioContext state: ${this.audioContext.state}`);
            // Will only work if using Firefox (and will take a short while) or where this method is called the first time with a user interaction, otherwise will be ignored
            this.audioContext.resume().then(() => {this.runUnlockedActions(2)});  
        }
        return this.audioContext;
    }

    /**
     * Called when we get a running AudioContext
     */
    runUnlockedActions(code) {
        if (this._unlocked) return;
        this._unlocked = true;
        console.log(`AudioContext unlocked (${code})`);
    }

    playHTMLaudio() {
        // https://github.com/swevans/unmute/blob/master/dev/src/unmute.ts
        // https://developer.mozilla.org/en-US/docs/Web/HTML/Element/audio
        console.log("Playing HTML audio");
        let tmp = document.createElement("div");
        tmp.innerHTML = "<audio x-webkit-airplay='deny'></audio>";  // Need this tag for Safari as disableRemotePlayback doesn't work
        let tag = tmp.children.item(0);
        tag.controls = false;  // don't show playback controls
        tag.disableRemotePlayback = true; // disables casting of audio to another device (and associated control appearing)
        tag.preload = "auto";
        // Set the src to a short bit of url encoded as a silent mp3
        // NOTE The silence MP3 must be high quality, when web audio sounds are played in parallel the web audio sound is mixed to match the bitrate of the html sound
        // 0.01 seconds of silence VBR220-260 Joint Stereo 859B
        tag.src = "data:audio/mpeg;base64,//uQxAAAAAAAAAAAAAAAAAAAAAAAWGluZwAAAA8AAAACAAACcQCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA//////////////////////////////////////////////////////////////////8AAABhTEFNRTMuMTAwA8MAAAAAAAAAABQgJAUHQQAB9AAAAnGMHkkIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//sQxAADgnABGiAAQBCqgCRMAAgEAH///////////////7+n/9FTuQsQH//////2NG0jWUGlio5gLQTOtIoeR2WX////X4s9Atb/JRVCbBUpeRUq//////////////////9RUi0f2jn/+xDECgPCjAEQAABN4AAANIAAAAQVTEFNRTMuMTAwVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQ==";
        // The str below is a "compressed" version using poor mans huffman encoding, saves about 0.5kb
        // tag.src = "data:audio/mpeg;base64,//uQx" + poorManHuffman(23, "A") + "WGluZwAAAA8AAAACAAACcQCA" + poorManHuffman(16, "gICA") + poorManHuffman(66, "/") + "8AAABhTEFNRTMuMTAwA8MAAAAAAAAAABQgJAUHQQAB9AAAAnGMHkkI" + poorManHuffman(320, "A") + "//sQxAADgnABGiAAQBCqgCRMAAgEAH" + poorManHuffman(15, "/") + "7+n/9FTuQsQH//////2NG0jWUGlio5gLQTOtIoeR2WX////X4s9Atb/JRVCbBUpeRUq" + poorManHuffman(18, "/") + "9RUi0f2jn/+xDECgPCjAEQAABN4AAANIAAAAQVTEFNRTMuMTAw" + poorManHuffman(97, "V") + "Q==";
        tag.loop = true;
        tag.load();
        tag.play();
    }

    closeAudioContext() {
        if (this.audioContext !== undefined) {
            this.audioContext.close();
            this.audioContext = undefined;
        }
    }

    isUnlocked() {
        return this.audioContext && this.audioContext.state === "running";
    }

    loadSample(url, key) {
        console.log(`Loading audio file (${key})`);
        let request = new XMLHttpRequest();
        request.open('GET', url, true);
        request.responseType = 'arraybuffer';
        request.onload = () => {
            // Load the data and keep a reference to it
            // console.log("File loaded");
            this.sounds[key] = request.response;
            this.decodeSample(key);
        };
        request.send();
    }

    decodeSample(key) {
        // Decoding seems to work even when AudioContext is suspended
        let ac = this.getAudioContext();
        console.log(`Decoding audio file (${key})`);
        // Promise-based syntax does not work for Safari desktop, need to use callback variant
        // https://developer.mozilla.org/en-US/docs/Web/API/BaseAudioContext/decodeAudioData
        ac.decodeAudioData(this.sounds[key], (buffer) => {
            this.sounds[key] = buffer;
        }, (e) => {
            console.log("Error decoding audio data: " + e);
        });
    }

    getSounds() {
        return this.sounds;
    }

    init() {
        if (!this.hasAudioContext) return;
        function startAudio() {
            console.log("Starting audio via user interaction");
            document.removeEventListener("mousedown", startAudio);
            document.removeEventListener("touchend", startAudio);
            morseAudioContext.getAudioContext();
        }
        document.addEventListener("mousedown", startAudio);
        document.addEventListener("touchend", startAudio);
    }
}

const morseAudioContext = new MorseAudioContext();

export default morseAudioContext;
