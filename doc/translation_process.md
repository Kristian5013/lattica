Translations
============

Lattica supports localisation of the GUI through [Qt Linguist](https://doc.qt.io/qt-6/qtlinguist-index.html)
`.ts` translation files, which live in [`src/qt/locale/`](/src/qt/locale/). Each
language has a `lattica_<locale>.ts` file (e.g. `lattica_de.ts`,
`lattica_ru.ts`); `lattica_en.ts` is the English source from which every other
translation is derived.

Unlike Bitcoin Core, Lattica does not use a hosted translation service
(Transifex). The `.ts` files are maintained directly in the repository.

### Writing translatable strings

* GUI strings must be wrapped in `tr("...")` (or `QT_TR_NOOP`/`QObject::tr`).
* Strings in the non-Qt code (the daemon, validation, RPC, …) that should be
  translatable use the bilingual `_("...")` macro; they are picked up into a
  generated `src/qt/latticastrings.cpp` so Qt Linguist can see them, under the
  `lattica-core` translation context (see `src/qt/main.cpp`).
* Follow [translation_strings_policy.md](translation_strings_policy.md) when
  adding or changing strings.

### Updating the source translation file

Whenever a translatable string in the source code is added or changed,
`lattica_en.ts` must be regenerated so the change is exposed to translators.
This is driven by the maintainer module [`share/qt/translate.cmake`](/share/qt/translate.cmake),
which uses `gettext` (`xgettext`) to extract the `_("...")` daemon strings into
`src/qt/latticastrings.cpp`, then runs `lupdate` and `lconvert` to refresh
`lattica_en.ts` (and `lattica_en.xlf`). `gettext` and the Qt Linguist tools
(`lupdate`, `lrelease`, `lconvert`) must be installed.

Only `lattica_en.ts` should be edited as a result of source changes — the other
`lattica_<locale>.ts` files hold the actual translations and are only updated
when (re)translating.

### Compiling translations into the binary

At build time, `lrelease` compiles each `lattica_<locale>.ts` into a binary
`.qm` file, which is embedded into `lattica-qt` through the
`lattica_locale.qrc` Qt resource (see [`src/qt/locale/CMakeLists.txt`](/src/qt/locale/CMakeLists.txt)).
No manual step is required; rebuilding `lattica-qt` picks up any `.ts` changes.

### Plurals and special handling

`.ts` entries may carry `<numerusform>` plural forms; keep them intact when
translating. See [translation_strings_policy.md](translation_strings_policy.md)
for guidance on plurals, placeholders (`%1`, `%n`) and other special cases.
