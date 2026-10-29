import { BgError } from "bgutils-js/utils";

export const VERSION = "2.0.2";

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
