/* Safari's native app extension answers sendNativeMessage requests. Adapt
 * bounded native reads/writes to the Port shape used by the shared worker.
 * The bridge carries the existing sealed protocol; it never decrypts values.
 * This script is loaded only by the Safari build. */
"use strict";
(() => {
  const MAX_BYTES = 64 * 1024;  // akdbx.protocol.MAX_MESSAGE
  const DEADLINE_MS = 12000;
  const encode = new TextEncoder();

  function event() {
    const listeners = new Set();
    return {
      addListener: listener => listeners.add(listener),
      removeListener: listener => listeners.delete(listener),
      hasListener: listener => listeners.has(listener),
      emit(value) {
        for (const listener of [...listeners]) {
          try { listener(value); } catch { /* A listener cannot break the transport. */ }
        }
      }
    };
  }

  function object(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  globalThis.akdbxConnectNative = host => {
    let session = null, closed = false;
    let writes = Promise.resolve();
    const onMessage = event(), onDisconnect = event();
    const port = {name: host, onMessage, onDisconnect, postMessage, disconnect};

    async function call(message) {
      let timer;
      try {
        const reply = await Promise.race([
          akdbxBrowser.runtime.sendNativeMessage(host, message),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("native timeout")), DEADLINE_MS); })
        ]);
        if (!object(reply) || reply.ok !== true) throw new Error("native broker unavailable");
        return reply;
      } finally {
        clearTimeout(timer);
      }
    }

    function disconnect() {
      if (closed) return;
      closed = true;
      const previous = session;
      session = null;
      if (previous !== null) void call({op: "close", session: previous}).catch(() => {});
      onDisconnect.emit(port);
    }

    async function read() {
      try {
        while (!closed) {
          const reply = await call({op: "read", session});
          if (closed) return;
          if (reply.message !== undefined) {
            if (!object(reply.message) || encode.encode(JSON.stringify(reply.message)).length > MAX_BYTES) {
              throw new Error("invalid native frame");
            }
            onMessage.emit(reply.message);
          } else {
            // Native reads wait for data with a bounded deadline. Also bound
            // a broken helper that accidentally returns empty replies at once.
            await new Promise(resolve => setTimeout(resolve, 10));
          }
        }
      } catch {
        disconnect();
      }
    }

    function postMessage(value) {
      if (closed) throw new Error("native port disconnected");
      const json = JSON.stringify(value);
      if (typeof json !== "string" || encode.encode(json).length > MAX_BYTES) {
        throw new Error("native frame exceeds limit");
      }
      const message = JSON.parse(json);
      if (!object(message)) throw new Error("invalid native frame");
      writes = writes.then(async () => {
        if (closed) return;
        if (session === null) {
          if (message.type !== "hello") throw new Error("native hello required");
          const reply = await call({op: "open", hello: message});
          if (typeof reply.session !== "string" || !/^[0-9a-f]{64}$/.test(reply.session)) {
            throw new Error("invalid native session");
          }
          if (closed) {
            void call({op: "close", session: reply.session}).catch(() => {});
            return;
          }
          session = reply.session;
          void read();
        } else {
          await call({op: "write", session, message});
        }
      }).catch(() => disconnect());
    }

    return port;
  };
})();
