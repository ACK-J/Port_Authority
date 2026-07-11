/**
 * Minimal test harness shared by Node-runnable *.test.js files.
 * No external dependencies — keeps the addon easy to audit and run.
 */

let passed = 0;
let failed = 0;
let currentSuite = "";

export function suite(name) {
    currentSuite = name;
    console.log(`\n▸ ${name}`);
}

export function assert(condition, message) {
    if (condition) {
        passed += 1;
        return;
    }
    failed += 1;
    const prefix = currentSuite ? `[${currentSuite}] ` : "";
    console.error(`  FAIL: ${prefix}${message}`);
}

export function assertEqual(actual, expected, message) {
    const same = Object.is(actual, expected) ||
        (actual !== null && expected !== null &&
            typeof actual === "object" && typeof expected === "object" &&
            JSON.stringify(actual) === JSON.stringify(expected));
    assert(
        same,
        `${message} (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`
    );
}

export async function assertRejects(fn, message) {
    try {
        await fn();
        assert(false, `${message} (expected rejection)`);
    } catch {
        assert(true, message);
    }
}

export function summary() {
    console.log(`\n${passed} passed, ${failed} failed`);
    return { passed, failed };
}

export function getCounters() {
    return { passed, failed };
}

/**
 * In-memory mock of `browser.storage.local`.
 */
export function createMockStorage(initial = {}) {
    const store = { ...initial };
    return {
        async get(key) {
            if (!(key in store)) return {};
            return { [key]: store[key] };
        },
        async set(obj) {
            Object.assign(store, obj);
        },
        async clear() {
            for (const key of Object.keys(store)) delete store[key];
        },
        _dump() {
            return { ...store };
        },
    };
}

/**
 * Simple mutex-style `navigator.locks` mock.
 * Exclusive locks run one at a time; shared locks may overlap with each other
 * but not with exclusive locks.
 */
export function installLockMock() {
    let exclusiveChain = Promise.resolve();
    let sharedActive = 0;
    let exclusiveActive = false;
    const sharedQueue = [];

    const flushShared = () => {
        if (exclusiveActive) return;
        while (sharedQueue.length > 0) {
            sharedQueue.shift()();
        }
    };

    const locks = {
        request(_name, optionsOrCallback, maybeCallback) {
            const hasOptions = typeof optionsOrCallback !== "function";
            const options = hasOptions ? optionsOrCallback : {};
            const callback = hasOptions ? maybeCallback : optionsOrCallback;
            const shared = options?.mode === "shared";

            if (shared) {
                return new Promise((resolve, reject) => {
                    const run = () => {
                        sharedActive += 1;
                        Promise.resolve()
                            .then(() => callback({ mode: "shared" }))
                            .then(resolve, reject)
                            .finally(() => {
                                sharedActive -= 1;
                            });
                    };

                    exclusiveChain.then(() => {
                        if (exclusiveActive) sharedQueue.push(run);
                        else run();
                    });
                });
            }

            const job = exclusiveChain.then(async () => {
                while (sharedActive > 0) {
                    await new Promise((r) => setTimeout(r, 0));
                }
                exclusiveActive = true;
                try {
                    return await callback({ mode: "exclusive" });
                } finally {
                    exclusiveActive = false;
                    flushShared();
                }
            });
            exclusiveChain = job.then(() => {}, () => {});
            return job;
        },
    };

    // Node's navigator may be a read-only getter — patch locks in place when possible.
    const existing = globalThis.navigator;
    if (existing && typeof existing === "object") {
        try {
            Object.defineProperty(existing, "locks", {
                configurable: true,
                writable: true,
                value: locks,
            });
            return;
        } catch {
            // fall through to replace navigator
        }
    }
    try {
        Object.defineProperty(globalThis, "navigator", {
            configurable: true,
            writable: true,
            value: { locks },
        });
    } catch {
        globalThis.navigator = { ...(existing || {}), locks };
    }
}

/**
 * Minimal DOM stub for createElement tests.
 */
export function installDocumentMock() {
    class FakeElement {
        constructor(tag) {
            this.tagName = String(tag).toUpperCase();
            this.attributes = {};
            this.childNodes = [];
        }
        setAttribute(key, value) {
            this.attributes[key] = String(value);
        }
        getAttribute(key) {
            return this.attributes[key] ?? null;
        }
        appendChild(node) {
            this.childNodes.push(node);
            return node;
        }
        replaceChildren(...nodes) {
            this.childNodes = [...nodes];
        }
    }

    globalThis.document = {
        createElement(tag) {
            return new FakeElement(tag);
        },
    };
}
