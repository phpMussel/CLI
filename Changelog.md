### v3.0.0

[2020.07.20; Maikuolan] First stable release for the phpMussel v3 CLI handler.

__*Why "v3.0.0" instead of "v1.0.0?"*__ Prior to phpMussel v3, the "phpMussel Core", "phpMussel CLI-mode", "phpMussel Front-End", and "phpMussel Uploads Handler" ("phpMussel Web") were all bundled together as a single repository (phpMussel/phpMussel). Since phpMussel v3, these each all have their own, separate repositories. I've opted to start releases at this repository (phpMussel/CLI) at *v3.0.0*, in order to avoid confusion with previous versions of the "phpMussel CLI-mode" which exist outside this repository.

### v3.1.0

[2020.12.04; Maikuolan]: Maintenance release (dependencies update, repository cleanup, etc).

### v3.1.1

[2021.01.10; Maikuolan]: Separated the code for performing outbound requests through cURL out to its own independent class.

### v3.1.2

[2022.03.24; Bug-fix; Maikuolan]: Fixed a bottleneck in the scan process caused by the readFileBlocks method (phpMussel/phpMussel#231).

### v3.1.3

[2022.08.18; Maikuolan]: Added L10N for Persian/Farsi, Hebrew, Malay, and Ukrainian.

[2022.08.23; Maikuolan]: Added some limited homoglyph support for some CLI commands.

### v3.1.4

[2022.11.20; Maikuolan]: Avoid packaging unnecessary files into dist.

### v3.1.5

[2023.04.30; Maikuolan]: Added L10N for Bulgarian, Czech, and Punjabi.

### v3.2.0

[2023.09.04; New Feature; Maikuolan]: Added colouration to phpMussel's CLI mode. Added L10N for Afrikaans and Romanian.

### 3.2.1

[2022.11.22; Maikuolan]: Maintenance release.
