/* Use the promise-based WebExtensions namespace in Firefox and Safari.
 * Chromium's promise-based chrome namespace remains unchanged. */
"use strict";
globalThis.akdbxBrowser = globalThis.browser || globalThis.chrome;
