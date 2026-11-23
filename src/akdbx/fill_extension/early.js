/* akdbx: runs only from the manifest's document_start entry, just before
 * content.js and before any page script. content.js trusts its own owner-probe
 * listener only when this flag is set; a content.js that the service worker
 * injects later finds no flag. */
"use strict";
globalThis.__akdbxEarly = true;
