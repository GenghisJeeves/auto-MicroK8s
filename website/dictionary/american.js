export var dictionary = {
    id: 'american',

    letter: {
        'A': '. -',
        'B': '- . . .',
        'C': '. .s.',
        'D': '- . .',
        'E': '.',
        'F': '. - .',
        'G': '- - .',
        'H': '. . . .',
        'I': '. .',
        'J': '- . - .',
        'K': '- . -',
        'L': 'd',
        'M': '- -',
        'N': '- .',
        'O': '.s.',
        'P': '. . . . .',
        'Q': '. . - .',
        'R': '.s. .',
        'S': '. . .',
        'T': '-',
        'U': '. . -',
        'V': '. . . -',
        'W': '. - -',
        'X': '. - . .',
        'Y': '. .s. .',
        'Z': '. . .s.',
        '1': '. - - .',
        '2': '. . - . .',
        '3': '. . . - .',
        '4': '. . . . -',
        '5': '- - -',
        '6': '. . . . . .',
        '7': '- - . .',
        '8': '- . . . .',
        '9': '- . . -',
        '0': 'D',
        '.': '. . - - . .',
        ',': '. - . -',
        ':': '- . -s.s.',
        '?': '- . . - .',
        '\'': '. . - .s. - . .',
        '-': '. . .s. - . .',
        '/': '. . -s-',
        '(': '. . . . .s- .',
        ')': '. . . . .s. .s. .',
        '"': '. . - .s- .', // fall back to using open quotes for straight
        '\u201c': '. . - .s- .', // open quotes
        '\u201d': '. . - .s- . - .', // close quotes
        '&': '.s. . .',
        '!': '- - - .',
        ';': '. . .s. .',
    },

    letterMatch: /^./,

    ratio: {
        '.': 1,
        '-': 2,
        'd': 4,
        'D': 5,
        ' ': -1,
        's': -1.5,
        'charSpace': -2,
        'wordSpace': -3
    },

    baseElement: '.',

    frequency: {
        '.': 550,
        '-': 550,
        'd': 550,
        'D': 550,
        ' ': 0,
        's': 0,
        'charSpace': 0,
        'wordSpace': 0
    },

    display: {
        morse: {
            '\\.': '.',
            '\\-': '-', // just a normal hyphen
            'd': '\u2e3a', // two-em dash
            'D': '\u2e3b', // three-em dash
            ' ': '',
            's': ' '
        },
        join: {
            charSpace: '   ',
            wordSpace: ' / '
        }
    },

    tokeniseMorse: function(morse) {
        morse = morse.trim();
        morse = morse.replace(/_/g, '-')
        morse = morse.replace(/\|/g, '/');
        morse = morse.replace(/\u2e3a/g, 'd');
        morse = morse.replace(/\u2e3b/g, 'D');
        morse = morse.replace(/[\r\n\t]+/g, '/');
        morse = morse.replace(/   +/g, '   ');
        morse = morse.replace(/([\.\-dD]  )([^ ])/g, '$1 $2');
        morse = morse.replace(/ *\/[ \/]*/g, '/');
        morse = morse.replace(/([\.\-dD]) (?=[\.\-dD])/g, '$1s');

        let words = morse.split('/');
        let tokens = words.map(word => word.split('   '));
        tokens = tokens.map(letters => letters.map(letter => letter.replace(/([\.\-])(?=[\.\-])/g, '$1 ')));
        return tokens;
    },

    morseMatch: new RegExp('^\\s*[\\.\\-_\u2e3a\u2e3b]+[\\.\\-_\u2e3a\u2e3b\\s\\/\\|]*$'),

    displayName: {
        keys: ['.', '-', 'd', 'D', ' ', 's', 'charSpace', 'wordSpace'],
        values: ['dit','dah','long dash','very long dash','short space','long space','inter-character space','word space']
    },

    options: {
    }
}
