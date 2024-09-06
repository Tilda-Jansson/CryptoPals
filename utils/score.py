def score_text(text: bytes) -> float:
    # Define character frequencies in English plaintext
    # These frequencies are simplified and represent typical English text
    english_unogram_freq = {
        "e": 12.575645,
        "t": 9.085226,
        "a": 8.000395,
        "o": 7.591270,
        "i": 6.920007,
        "n": 6.903785,
        "s": 6.340880,
        "h": 6.236609,
        "r": 5.959034,
        "d": 4.317924,
        "l": 4.057231,
        "u": 2.841783,
        "c": 2.575785,
        "m": 2.560994,
        "f": 2.350463,
        "w": 2.224893,
        "g": 1.982677,
        "y": 1.900888,
        "p": 1.795742,
        "b": 1.535701,
        "v": 0.981717,
        "k": 0.739906,
        "x": 0.179556,
        "j": 0.145188,
        "q": 0.117571,
        "z": 0.079130,
        " ": 19.18182 
    }
    # Calculate the score of a text based on character frequency
    return sum([english_unogram_freq.get(chr(byte).lower(), 0) for byte in text])
