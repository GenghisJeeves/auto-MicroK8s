import argparse
import logging
import time
from typing import Any

import numpy as np
import sounddevice as sd
from scipy.io import wavfile  # For saving audio files

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Morse code mapping
MORSE_CODE_DICT: dict[str, str] = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    "0": "-----",
    " ": "/",
    ".": ".-.-.-",
    ",": "--..--",
    ":": "---...",
    "?": "..--..",
    "'": ".----.",
    "-": "-....-",
    "/": "-..-.",
    "@": ".--.-.",
    "=": "-...-",
    "(": "-.--.",
    ")": "-.--.-",
}


def text_to_morse(text: str) -> str:
    """Convert text to Morse code."""
    morse: list[str] = []
    for char in text.upper():
        if char in MORSE_CODE_DICT:
            morse.append(MORSE_CODE_DICT[char])
    return " ".join(morse)


def generate_tone(
    frequency: float, duration: float, sample_rate: int = 44100
) -> np.ndarray[Any, np.dtype[Any]]:
    """Generate a sine wave tone."""
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    tone = np.sin(2 * np.pi * frequency * t)
    # Apply fade in/out to reduce clicks
    fade_ms = min(100, int(duration * 1000 / 4))
    fade_samples = int(fade_ms * sample_rate / 1000)
    fade_in = np.linspace(0, 1, fade_samples)
    fade_out = np.linspace(1, 0, fade_samples)
    tone[:fade_samples] *= fade_in
    tone[-fade_samples:] *= fade_out
    return tone


def create_morse_audio(
    morse: str,
    frequency: float,
    dot_duration: float,
    dash_duration: float,
    symbol_gap: float,
    char_gap: float,
    word_gap: float,
    volume: float,
    sample_rate: int,
) -> np.ndarray[Any, np.dtype[Any]]:
    """
    Create a complete audio array for Morse code without playing it.
    Returns the full audio array that can be played or saved.
    """
    # Calculate silence durations in samples
    symbol_gap_samples = int(symbol_gap * sample_rate)
    char_gap_samples = int(char_gap * sample_rate)
    word_gap_samples = int(word_gap * sample_rate)

    # Create silence arrays
    symbol_silence = np.zeros(symbol_gap_samples)
    char_silence = np.zeros(char_gap_samples)
    word_silence = np.zeros(word_gap_samples)

    # Initialize an empty array to store the full audio
    audio_segments: list[np.ndarray[Any, np.dtype[Any]]] = []

    for i, symbol in enumerate(morse):
        if symbol == ".":
            # Add a dot
            dot_tone = generate_tone(frequency, dot_duration, sample_rate) * volume
            audio_segments.append(dot_tone)
            if i < len(morse) - 1 and morse[i + 1] not in [" ", "/"]:
                audio_segments.append(symbol_silence)
        elif symbol == "-":
            # Add a dash
            dash_tone = generate_tone(frequency, dash_duration, sample_rate) * volume
            audio_segments.append(dash_tone)
            if i < len(morse) - 1 and morse[i + 1] not in [" ", "/"]:
                audio_segments.append(symbol_silence)
        elif symbol == " ":
            # Character gap
            audio_segments.append(char_silence)
        elif symbol == "/":
            # Word gap
            audio_segments.append(word_silence)

    # Concatenate all audio segments
    full_audio = np.concatenate(audio_segments)
    return full_audio


def play_morse_audio(
    morse: str,
    frequency: float,
    dot_duration: float,
    dash_duration: float,
    symbol_gap: float,
    char_gap: float,
    word_gap: float,
    volume: float,
    sample_rate: int,
) -> None:
    """Play Morse code as audio through speakers."""
    for i, symbol in enumerate(morse):
        if symbol == ".":
            # Play a dot
            tone = generate_tone(frequency, dot_duration, sample_rate) * volume
            sd.play(tone, sample_rate)
            sd.wait()
            if i < len(morse) - 1 and morse[i + 1] not in [" ", "/"]:
                time.sleep(symbol_gap)
        elif symbol == "-":
            # Play a dash
            tone = generate_tone(frequency, dash_duration, sample_rate) * volume
            sd.play(tone, sample_rate)
            sd.wait()
            if i < len(morse) - 1 and morse[i + 1] not in [" ", "/"]:
                time.sleep(symbol_gap)
        elif symbol == " ":
            # Character gap
            time.sleep(char_gap)
        elif symbol == "/":
            # Word gap
            time.sleep(word_gap)


def transmit_morse(
    message: str,
    frequency: float = 800,
    wpm: int = 15,
    volume: float = 0.5,
    sample_rate: int = 44100,
    output_file: str | None = None,
) -> None:
    """
    Transmit a message in Morse code through the computer's speaker or save to file.

    Args:
        message: Text message to convert to Morse code
        frequency: Tone frequency in Hz
        wpm: Speed in words per minute
        volume: Volume level (0.0 to 1.0)
        sample_rate: Audio sample rate
        output_file: If provided, save audio to this file instead of playing it
    """
    # Calculate timings (in seconds) based on WPM
    unit_duration = 60 / (50 * wpm)  # Duration of one unit in seconds

    dot_duration = unit_duration
    dash_duration = 3 * unit_duration
    symbol_gap = unit_duration
    char_gap = 3 * unit_duration
    word_gap = 7 * unit_duration

    # Start pattern (_._._)
    start_pattern = "-.-.-."

    # End pattern (..._._)
    end_pattern = "...-.-."

    # Convert message to Morse code
    morse_message = text_to_morse(message)

    logger.info(f"Transmitting message: {message}")
    logger.info(f"Morse code: {start_pattern} {morse_message} {end_pattern}")

    # Combine patterns and message with appropriate spacing
    full_morse = start_pattern + " " + morse_message + " " + end_pattern

    if output_file:
        # Create audio data and save to file
        audio_data = create_morse_audio(
            full_morse,
            frequency,
            dot_duration,
            dash_duration,
            symbol_gap,
            char_gap,
            word_gap,
            volume,
            sample_rate,
        )

        # Scale to 16-bit integer range for WAV file
        audio_normalized = np.int16(audio_data * 32767)

        # Save as WAV file
        wavfile.write(output_file, sample_rate, audio_normalized)  # type: ignore
        logger.info(f"Audio saved to {output_file}")
    else:
        # Play the Morse code through speakers
        logger.info("Playing audio through speakers")
        play_morse_audio(
            full_morse,
            frequency,
            dot_duration,
            dash_duration,
            symbol_gap,
            char_gap,
            word_gap,
            volume,
            sample_rate,
        )

    logger.info("Transmission complete")


def main():
    parser = argparse.ArgumentParser(description="Transmit a message in Morse code")
    parser.add_argument("message", type=str, help="Message to transmit")
    parser.add_argument(
        "--frequency", type=float, default=800, help="Tone frequency in Hz"
    )
    parser.add_argument("--wpm", type=int, default=15, help="Speed in words per minute")
    parser.add_argument(
        "--volume", type=float, default=0.5, help="Volume level (0.0 to 1.0)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Save to audio file instead of playing through speakers",
    )

    args = parser.parse_args()

    transmit_morse(
        args.message, args.frequency, args.wpm, args.volume, output_file=args.output
    )


if __name__ == "__main__":
    main()
