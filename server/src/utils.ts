import { BgError } from "bgutils-js/utils";
import { AsyncLocalStorage } from "node:async_hooks";
import { format } from "node:util";

export const VERSION = "2.0.2";

// Tag shown on every log line written while handling a request or a
// background job, so interleaved concurrent requests can be told apart
export const logContext = new AsyncLocalStorage<string>();

const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const CYAN = "\x1b[36m";
// [label, color of the label, color of the message]
const LOG_LEVELS = {
    debug: ["DEBUG", "\x1b[90m", "\x1b[90m"],
    log: ["INFO ", "\x1b[32m", ""],
    info: ["INFO ", "\x1b[32m", ""],
    warn: ["WARN ", "\x1b[33m", "\x1b[33m"],
    error: ["ERROR", "\x1b[31m", "\x1b[31m"],
} as const;

function timestamp(): string {
    const d = new Date();
    const pad = (n: number, width = 2) => String(n).padStart(width, "0");
    return (
        `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
        `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
        `.${pad(d.getMilliseconds(), 3)}`
    );
}

// Prefix every console line with a timestamp, level and log context tag,
// colored when the stream is a terminal; NO_COLOR and FORCE_COLOR override
// the detection. Only for the server: script mode's stdout is parsed by
// the plugin.
export function formatConsoleOutput() {
    for (const [method, [label, labelColor, msgColor]] of Object.entries(
        LOG_LEVELS,
    ) as [keyof typeof LOG_LEVELS, (typeof LOG_LEVELS)["log"]][]) {
        const original = console[method].bind(console);
        const stream =
            method === "warn" || method === "error"
                ? process.stderr
                : process.stdout;
        const color = process.env.NO_COLOR
            ? false
            : !!process.env.FORCE_COLOR || !!stream.isTTY;
        console[method] = (...args: unknown[]) => {
            const msg = format(...args);
            const tag = logContext.getStore();
            original(
                color
                    ? `${DIM}${timestamp()}${RESET} ${labelColor}${label}${RESET} ` +
                          (tag ? `${CYAN}[${tag}]${RESET} ` : "") +
                          (msgColor ? `${msgColor}${msg}${RESET}` : msg)
                    : `${timestamp()} ${label} ` +
                          (tag ? `[${tag}] ` : "") +
                          msg,
            );
        };
    }
}

// Seconds since a performance.now() timestamp, formatted for logs
export function elapsed(start: number): string {
    return `${((performance.now() - start) / 1000).toFixed(2)}s`;
}

export function strerror(e: any, update?: boolean): string {
    const msg =
        e instanceof BgError
            ? `BgError: ${e.message} (info: ${JSON.stringify(e.info)})`
            : e instanceof Error
              ? `${e.name}: ${e.message}` +
                (e.cause && e.cause !== e
                    ? ` (caused by ${strerror(e.cause)})`
                    : "")
              : `Unknown error: ${JSON.stringify(e)}`;
    if (update) {
        const idx = msg.indexOf(": ");
        e.message = idx == -1 ? msg : msg.slice(idx + 2);
    }
    return msg;
}
