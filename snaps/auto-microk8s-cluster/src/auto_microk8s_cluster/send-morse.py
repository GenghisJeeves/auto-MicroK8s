import argparse
import logging
import time

import numpy as np
import sounddevice as sd

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
    morse = []
    for char in text.upper():
        if char in MORSE_CODE_DICT:
            morse.append(MORSE_CODE_DICT[char])
    return " ".join(morse)


def generate_tone(
    frequency: float, duration: float, sample_rate: int = 44100
) -> np.ndarray:
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
    """Play Morse code as audio."""
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
) -> None:
    """
    Transmit a message in Morse code through the computer's speaker.
    The message starts with _._._  followed by the provided string
    and ends with ..._._

    Args:
        message: Text message to convert to Morse code
        frequency: Tone frequency in Hz
        wpm: Speed in words per minute
        volume: Volume level (0.0 to 1.0)
        sample_rate: Audio sample rate
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

    # Play the Morse code
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

    args = parser.parse_args()

    transmit_morse(args.message, args.frequency, args.wpm, args.volume)


if __name__ == "__main__":
    main()
