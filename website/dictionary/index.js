import * as international from "./international.js";
import * as american from "./american.js";
import * as cyrillic from "./cyrillic.js";
import * as cyrillicUkraine from "./cyrillic-ukraine.js";
import * as hebrew from "./hebrew.js";
import * as arabic from "./arabic.js";

export var dictionaries = {};

dictionaries.international = international.dictionary;
dictionaries.american = american.dictionary;
dictionaries.cyrillic = cyrillic.dictionary;
dictionaries.cyrillicUkraine = cyrillicUkraine.dictionary;
dictionaries.hebrew = hebrew.dictionary;
dictionaries.arabic = arabic.dictionary;
