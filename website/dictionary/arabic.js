export var dictionary = {
    id: 'arabic',

    letter: {
        'ا': '. -',
        'ب': '- . . .',
        'ت': '-',
        'ث': '- . - .',
        'ج': '. - - -',
        'ح': '. . . .',
        'خ': '- - -',
        'د': '- . .',
        'ذ': '- - . .',
        'ر': '. - .',
        'ز': '- - - .',
        'س': '. . .',
        'ش': '- - - -',
        'ص': '- . . -',
        'ض': '. . . -',
        'ط': '. . -',
        'ظ': '- . - -',
        'ع': '. - . -',
        'غ': '- - .',
        'ف': '. . - .',
        'ق': '- - . -',
        'ك': '- . -',
        'ل': '. - . .',
        'م': '- -',
        'ن': '- .',
        'ه': '. . - - . .',
        'و': '. - -',
        'ي': '. .',
        'ﺀ': '.',

        '1': '. - - - -',
        '2': '. . - - -',
        '3': '. . . - -',
        '4': '. . . . -',
        '5': '. . . . .',
        '6': '- . . . .',
        '7': '- - . . .',
        '8': '- - - . .',
        '9': '- - - - .',
        '0': '- - - - -',

        // '.': '. - . - . -',
        // ',': '- - . . - -',
        // ':': '- - - . . .',
        // '?': '. . - - . .',
        // '\'': '. - - - - .',
        // '-': '- . . . . -',
        // '/': '- . . - .',
        // '(': '- . - - .',
        // ')': '- . - - . -',
        // '“': '. - . . - .',  // U+201C
        // '”': '. - . . - .',  // U+201D
        // '‘': '. - . . - .',  // U+2018
        // '’': '. - . . - .',  // U+2019
        // '"': '. - . . - .',
        // '@': '. - - . - .',
        // '=': '- . . . -',
        // '&': '. - . . .',
        // '+': '. - . - .',
        // '!': '- . - . - -',
    },

    letterMatch: /^./,

    /* 'charSpace' and 'wordSpace' are mandatory. The other symbols are dictionary dependent. */
    ratio: {
        '.': 1,
        '-': 3,
        ' ': -1,
        'charSpace': -3,
        'wordSpace': -7
    },

    baseElement: '.',

    frequency: {
        '.': 550,
        '-': 550,
        ' ': 0,
        'charSpace': 0,
        'wordSpace': 0
    },

    display: {
        morse: {
            '\\.': '.',
            '\\-': '-',
            ' ': ''
        },
        join: {
            charSpace: ' ',
            wordSpace: ' / '
        }
    },

    tokeniseMorse: function(morse) {
        morse = morse.trim();
        morse = morse.replace(/_/g, '-')
        morse = morse.replace(/\|/g, '/');
        morse = morse.replace(/\s+/g, ' ');
        morse = morse.replace(/\s*\/[\s\/]*/g, '/');
        let words = morse.split('/');
        let tokens = words.map(word => word.split(' '));
        tokens = tokens.map(letters => letters.map(letter => letter.replace(/(.)(?=.)/g, '$1 ')));
        return tokens;
    },

    morseMatch: new RegExp('^\\s*[\\.\\-_]+[\\.\\-_\\s\\/\\|]*$'),

    displayName: {
        keys: ['.', '-', ' ', 'charSpace', 'wordSpace'],
        values: ['Dit length', 'Dah length', 'Intra-character space', 'Inter-character space', 'Inter-word space']
    },

    options: {
    }
}
