import axios, { AxiosRequestConfig } from "axios";
import {
    buildURL,
    getHeaders,
    parseLooseJSON,
    USER_AGENT,
} from "bgutils-js/utils";
import type {
    IBotguardClientSideBgChallenge,
    WebPoSignalOutput,
} from "bgutils-js/shared-types";
import { BotGuardClient } from "bgutils-js/botguard";
import { WebPoMinter } from "bgutils-js/webpo";
import { Agent } from "node:https";
import { isIPv4, isIPv6 } from "node:net";
import { ProxyAgent } from "proxy-agent";
import { JSDOM } from "jsdom";
import { Innertube, Context as InnertubeContext } from "youtubei.js";
import { elapsed, logContext, strerror } from "./utils.ts";

// The plugin gives up on a request after this long
const PLUGIN_TIMEOUT_SECS = 20;

function describeIp(ip: string): string {
    const family = isIPv6(ip) ? "IPv6" : isIPv4(ip) ? "IPv4" : "unknown";
    return `${ip} (${family})`;
}

interface PotContext {
    fetch: typeof fetch;
    globalObj: typeof globalThis;
}

interface YoutubeSessionData {
    poToken: string;
    contentBinding: string;
    expiresAt: Date;
}

const SUPPORTED_PROXY_PROTOCOLS = new Set([
    "http:",
    "https:",
    "socks:",
    "socks4:",
    "socks4a:",
    "socks5:",
    "socks5h:",
]);

export class InvalidProxyError extends Error {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "InvalidProxyError";
    }
}

export interface YoutubeSessionDataCaches {
    [contentBinding: string]: YoutubeSessionData;
}

class Logger {
    readonly debug: (msg: string) => void;
    readonly log: (msg: string) => void;
    readonly warn: (msg: string) => void;
    readonly error: (msg: string) => void;

    constructor(shouldLog = true) {
        if (shouldLog) {
            this.debug = (msg: string) => {
                console.debug(msg);
            };
            this.log = (msg: string) => {
                console.log(msg);
            };
        } else {
            this.debug = this.log = () => {};
        }
        this.warn = (msg: string) => {
            console.warn(msg);
        };
        this.error = (msg: string) => {
            console.error(msg);
        };
    }
}

class ProxySpec {
    public proxyUrl?: URL;
    public sourceAddress?: string;
    public disableTlsVerification: boolean = false;
    public readonly ipFamily?: number;
    constructor({ sourceAddress, disableTlsVerification }: Partial<ProxySpec>) {
        this.sourceAddress = sourceAddress;
        this.disableTlsVerification = disableTlsVerification || false;
        if (!this.sourceAddress) {
            this.ipFamily = undefined;
        } else {
            this.ipFamily = this.sourceAddress?.includes(":") ? 6 : 4;
        }
    }

    public get proxy(): string | undefined {
        return this.proxyUrl?.href;
    }

    // The proxy URL with its password masked
    public get loggableProxy(): string | undefined {
        const { proxy, proxyUrl } = this;
        return proxyUrl?.password
            ? proxy!.replace(proxyUrl.password, "****")
            : proxy;
    }

    public set proxy(newProxy: string | undefined) {
        if (newProxy) {
            // Normalize and sanitize the proxy URL
            let proxyUrl: URL;
            try {
                proxyUrl = new URL(newProxy);
            } catch {
                newProxy = `http://${newProxy}`;
                try {
                    proxyUrl = new URL(newProxy);
                } catch (e) {
                    throw new InvalidProxyError(
                        `Invalid proxy URL: ${newProxy}`,
                        { cause: e },
                    );
                }
            }
            if (!SUPPORTED_PROXY_PROTOCOLS.has(proxyUrl.protocol)) {
                throw new InvalidProxyError(
                    `Unsupported proxy protocol: ${proxyUrl.protocol}`,
                );
            }
            this.proxyUrl = proxyUrl;
        }
    }

    public asDispatcher(
        this: Readonly<this>,
        logger: Logger,
    ): Agent | undefined {
        const { proxyUrl, sourceAddress, disableTlsVerification } = this;
        if (!proxyUrl) {
            return new Agent({
                localAddress: sourceAddress,
                family: this.ipFamily,
                rejectUnauthorized: !disableTlsVerification,
            });
        }
        // Proxy must be a string as long as the URL is truthy
        const pxyStr = this.proxy!;
        const loggedProxy = this.loggableProxy;

        logger.debug(`Using proxy: ${loggedProxy}`);
        try {
            return new ProxyAgent({
                getProxyForUrl: () => pxyStr,
                localAddress: sourceAddress,
                family: this.ipFamily,
                rejectUnauthorized: !disableTlsVerification,
            });
        } catch (e) {
            throw new Error(`Failed to create proxy agent for ${loggedProxy}`, {
                cause: e,
            });
        }
    }
}

class CacheSpec {
    constructor(
        public pxySpec: ProxySpec,
        public ip: string | null,
    ) {}
    public get key(): string {
        return JSON.stringify(
            this.ip || [this.pxySpec.proxy, this.pxySpec.sourceAddress],
        );
    }
    // For logs; unlike key, this never contains the proxy password
    public get label(): string {
        if (this.ip) return `client IP ${describeIp(this.ip)}`;
        const { loggableProxy, sourceAddress } = this.pxySpec;
        return (
            "unknown client IP, " +
            (loggableProxy ? `via proxy ${loggableProxy}` : "direct") +
            (sourceAddress ? ` from ${sourceAddress}` : "")
        );
    }
}

type TokenMinter = {
    expiry: Date;
    integrityToken: string;
    minter: WebPoMinter;
    // Whether a POT was minted with it; idle minters aren't refreshed
    used: boolean;
};

type MinterCache = Map<string, TokenMinter>;

// Collected while generating a minter, for its summary log line
type MinterStats = {
    challengeSource?: string;
    interpreterCached?: boolean;
    // The IP YouTube saw this server's own requests come from
    serverIp?: string;
};

export type ChallengeData = {
    interpreterUrl: {
        privateDoNotAccessOrElseTrustedResourceUrlWrappedValue: string;
    };
    interpreterHash: string;
    program: string;
    globalName: string;
    clientExperimentsStateBlob: string;
};

export class SessionManager {
    // hardcoded API key that has been used by youtube for years
    private static readonly REQUEST_KEY = "O43z0dpjhgX20SCx4KAo";
    private static readonly REFRESH_LEAD_MS = 10 * 60 * 1000;
    private static readonly REFRESH_RETRY_MS = 60 * 1000;
    private static hasDom = false;
    private _minterCache: MinterCache = new Map();
    // Minters being generated, keyed like _minterCache, so concurrent
    // requests share one BotGuard run instead of each starting their own
    private _pendingMinters = new Map<string, Promise<TokenMinter>>();
    private _interpreterCache?: { url: string; js: string };
    private _refreshTimers = new Map<string, ReturnType<typeof setTimeout>>();
    private TOKEN_TTL_HOURS: number;
    private logger: Logger;

    constructor(
        shouldLog = true,
        // This needs to be reworked as POTs are IP-bound
        private youtubeSessionDataCaches?: YoutubeSessionDataCaches,
        // Regenerate minters shortly before they expire instead of on the
        // next request. Only for long-running processes, since the timers
        // keep the process alive.
        private backgroundRefresh = false,
    ) {
        this.logger = new Logger(shouldLog);
        this.TOKEN_TTL_HOURS = process.env.TOKEN_TTL
            ? parseInt(process.env.TOKEN_TTL)
            : 6;
        if (!SessionManager.hasDom) {
            const dom = new JSDOM(
                '<!DOCTYPE html><html lang="en"><head><title></title></head><body></body></html>',
                {
                    url: "https://www.youtube.com/",
                    referrer: "https://www.youtube.com/",
                    resources: { userAgent: USER_AGENT },
                },
            );

            Object.assign(globalThis, {
                window: dom.window,
                document: dom.window.document,
                location: dom.window.location,
                origin: dom.window.origin,
            });

            if (!Reflect.has(globalThis, "navigator")) {
                Object.defineProperty(globalThis, "navigator", {
                    value: dom.window.navigator,
                });
            }
            SessionManager.hasDom = true;
        }
    }

    public invalidateCaches() {
        this.setYoutubeSessionDataCaches();
        this._minterCache.clear();
        this._refreshTimers.forEach((timer) => clearTimeout(timer));
        this._refreshTimers.clear();
    }

    public invalidateIT() {
        this._minterCache.forEach((minterCache) => {
            minterCache.expiry = new Date(0);
        });
    }

    public cleanupCaches() {
        for (const contentBinding in this.youtubeSessionDataCaches) {
            const sessionData = this.youtubeSessionDataCaches[contentBinding];
            if (sessionData && new Date() > sessionData.expiresAt)
                delete this.youtubeSessionDataCaches[contentBinding];
        }
    }

    public getYoutubeSessionDataCaches(cleanup = false) {
        if (cleanup) this.cleanupCaches();
        return this.youtubeSessionDataCaches;
    }

    public setYoutubeSessionDataCaches(
        youtubeSessionData?: YoutubeSessionDataCaches,
    ) {
        this.youtubeSessionDataCaches = youtubeSessionData;
    }

    public get minterCache(): MinterCache {
        return this._minterCache;
    }

    // PATCH(unstem 2026-08): fetch the YT homepage (through the caller's
    // proxy) and extract a self-consistent (ytcfg, ytAtN challenge) pair.
    // Injects yt.config_ into the BotGuard global object so the snapshot
    // sees EVENT_ID. Returns undefined on any failure (caller falls back).
    private async getChallengeFromHomepage(
        potCtx: PotContext,
        stats: MinterStats,
    ): Promise<ChallengeData | undefined> {
        try {
            const pageResponse = await potCtx.fetch("https://www.youtube.com", {
                method: "GET",
                headers: {
                    accept: "*/*",
                    "accept-language": "en-US,en;q=0.7",
                    "user-agent": USER_AGENT,
                },
            });
            const pageHtml: string = await pageResponse.text();

            const ytcfgMatch = pageHtml.match(/ytcfg\.set\(({.+?})\);/s);
            if (ytcfgMatch) {
                const ytObj = { config_: JSON.parse(ytcfgMatch[1] as string) };
                const g: any = globalThis as any;
                g.yt = ytObj; // BotGuard reads yt.config_.EVENT_ID
                if (g.window) g.window.yt = ytObj;
                stats.serverIp =
                    ytObj.config_.INNERTUBE_CONTEXT?.client?.remoteHost;
            } else {
                this.logger.warn(
                    "homepage-challenge: no ytcfg found (EVENT_ID missing)",
                );
            }

            const attMatch = pageHtml.match(
                /window\.ytAtN\(\s*({[\s\S]*?})\s*\)/,
            );
            if (!attMatch) {
                this.logger.warn(
                    "homepage-challenge: no ytAtN challenge in page",
                );
                return undefined;
            }
            const attData: any = parseLooseJSON(attMatch[1] as string);
            const bgChallenge = attData?.R?.bgChallenge;
            if (!bgChallenge?.program || !bgChallenge?.interpreterUrl) {
                this.logger.warn(
                    "homepage-challenge: ytAtN payload missing bgChallenge",
                );
                return undefined;
            }
            return bgChallenge as ChallengeData;
        } catch (e) {
            this.logger.warn(
                `homepage-challenge: failed (${e?.message}), falling back`,
            );
            return undefined;
        }
    }

    private async getDescrambledChallenge(
        potCtx: PotContext,
        stats: MinterStats,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
    ): Promise<IBotguardClientSideBgChallenge> {
        try {
            // PATCH(unstem 2026-08): always mint from the homepage's
            // (ytcfg, ytAtN) pair — plugin-passed challenges lack their
            // page's ytcfg/EVENT_ID and /att/get tokens are rejected.
            const homepageChallenge = await this.getChallengeFromHomepage(
                potCtx,
                stats,
            );
            if (homepageChallenge) {
                challenge = homepageChallenge;
                stats.challengeSource = "homepage";
            } else if (challenge) {
                stats.challengeSource = "plugin";
            }
            if (!challenge) {
                stats.challengeSource = "/att/get (legacy fallback)";
                const attGetResponse = await potCtx.fetch(
                    "https://www.youtube.com/youtubei/v1/att/get?prettyPrint=false",
                    {
                        method: "POST",
                        headers: {
                            ...getHeaders(),
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                            context: innertubeContext || {
                                client: {
                                    clientName: "WEB",
                                    clientVersion: "2.20260817.01.00",
                                },
                            },
                            engagementType: "ENGAGEMENT_TYPE_UNBOUND",
                        }),
                    },
                );
                const attestation = await attGetResponse.json();
                if (!attestation)
                    throw new Error("Failed to get challenge from /att/get");
                challenge = attestation.bgChallenge as ChallengeData;
            }
            const { program, globalName, interpreterHash } = challenge;
            const { privateDoNotAccessOrElseTrustedResourceUrlWrappedValue } =
                challenge.interpreterUrl;
            const interpreterJS = await this.getInterpreterJS(
                potCtx,
                stats,
                `https:${privateDoNotAccessOrElseTrustedResourceUrlWrappedValue}`,
            );
            return {
                program,
                globalName,
                interpreterHash,
                interpreterJavascript: {
                    privateDoNotAccessOrElseSafeScriptWrappedValue:
                        interpreterJS,
                },
                interpreterUrl: {
                    privateDoNotAccessOrElseTrustedResourceUrlWrappedValue,
                },
            };
        } catch (e) {
            throw new Error("Could not get BotGuard challenge", { cause: e });
        }
    }

    // The interpreter URL is versioned, so the script only needs to be
    // fetched again when YouTube rotates it
    private async getInterpreterJS(
        potCtx: PotContext,
        stats: MinterStats,
        url: string,
    ): Promise<string> {
        stats.interpreterCached = this._interpreterCache?.url === url;
        if (stats.interpreterCached) return this._interpreterCache!.js;
        const interpreterJSResponse = await potCtx.fetch(url);
        const js = await interpreterJSResponse.text();
        this._interpreterCache = { url, js };
        return js;
    }

    private scheduleRefresh(
        cacheSpec: CacheSpec,
        potCtx: PotContext,
        innertubeContext: InnertubeContext | undefined,
        delayMs: number,
    ) {
        const { key, label } = cacheSpec;
        clearTimeout(this._refreshTimers.get(key));
        this.logger.debug(
            `Next background refresh of the POT minter for ${label} at ` +
                new Date(Date.now() + delayMs).toISOString(),
        );
        // Own log tag, rather than that of the request that scheduled it
        const timer = setTimeout(
            () =>
                logContext.run("refresh", async () => {
                    this._refreshTimers.delete(key);
                    const current = this._minterCache.get(key);
                    if (!current) return;
                    if (!current.used) {
                        // Nobody minted with this one since the last refresh, so
                        // stop keeping it warm; the next request regenerates it
                        this._minterCache.delete(key);
                        this.logger.log(
                            `Dropped idle POT minter for ${label}, ` +
                                `${this._minterCache.size} minter(s) left`,
                        );
                        return;
                    }
                    this.logger.log(
                        `Refreshing POT minter for ${label} in background`,
                    );
                    try {
                        // The plugin-supplied challenge is long stale by now
                        await this.generateTokenMinter(
                            cacheSpec,
                            potCtx,
                            undefined,
                            innertubeContext,
                        );
                    } catch (e) {
                        const retryMs = SessionManager.REFRESH_RETRY_MS;
                        const canRetry =
                            Date.now() + retryMs < current.expiry.getTime();
                        this.logger.warn(
                            `Background minter refresh for ${label} failed (${strerror(e)})` +
                                (canRetry
                                    ? `, retrying in ${retryMs / 1000}s`
                                    : ", the next request will regenerate it"),
                        );
                        if (canRetry)
                            this.scheduleRefresh(
                                cacheSpec,
                                potCtx,
                                innertubeContext,
                                retryMs,
                            );
                    }
                }),
            delayMs,
        );
        this._refreshTimers.set(key, timer);
    }

    private generateTokenMinter(
        cacheSpec: CacheSpec,
        potCtx: PotContext,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
    ): Promise<TokenMinter> {
        const { key } = cacheSpec;
        let pending = this._pendingMinters.get(key);
        if (!pending) {
            pending = this.createTokenMinter(
                cacheSpec,
                potCtx,
                challenge,
                innertubeContext,
            ).finally(() => this._pendingMinters.delete(key));
            this._pendingMinters.set(key, pending);
        } else {
            this.logger.log(
                `Waiting for the POT minter for ${cacheSpec.label} that is already being generated`,
            );
        }
        return pending;
    }

    private async createTokenMinter(
        cacheSpec: CacheSpec,
        potCtx: PotContext,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
    ): Promise<TokenMinter> {
        const start = performance.now();
        const stats: MinterStats = {};
        const descrambledChallenge = await this.getDescrambledChallenge(
            potCtx,
            stats,
            challenge,
            innertubeContext,
        );
        const challengeTime = elapsed(start);

        const { program, globalName } = descrambledChallenge;
        const interpreterJavascript =
            descrambledChallenge.interpreterJavascript
                ?.privateDoNotAccessOrElseSafeScriptWrappedValue;

        const botguardStart = performance.now();
        if (interpreterJavascript) {
            new Function(interpreterJavascript)();
        } else throw new Error("Could not load VM");

        let bgClient: BotGuardClient;
        try {
            bgClient = await BotGuardClient.create({
                program,
                globalName,
                globalObject: potCtx.globalObj,
            });
        } catch (e) {
            throw new Error(`Failed to create BG client.`, { cause: e });
        }
        try {
            const webPoSignalOutput: WebPoSignalOutput = [];
            const botguardResponse = await bgClient.snapshot({
                webPoSignalOutput,
            });
            const botguardTime = elapsed(botguardStart);
            const integrityTokenStart = performance.now();
            const integrityTokenResp = await potCtx.fetch(
                buildURL("GenerateIT"),
                {
                    method: "POST",
                    headers: getHeaders(),
                    body: JSON.stringify([
                        SessionManager.REQUEST_KEY,
                        botguardResponse,
                    ]),
                },
            );

            const [
                integrityToken,
                estimatedTtlSecs,
                mintRefreshThreshold,
                websafeFallbackToken,
            ] = (await integrityTokenResp.json()) as [
                string,
                number,
                number,
                string,
            ];
            const integrityTokenTime = elapsed(integrityTokenStart);

            const integrityTokenData = {
                integrityToken,
                estimatedTtlSecs,
                mintRefreshThreshold,
                websafeFallbackToken,
            };

            if (!integrityToken)
                throw new Error(
                    `Unexpected empty integrity token, response: ${JSON.stringify(integrityTokenData)}`,
                );
            this.logger.debug(
                `Generated IntegrityToken: ${JSON.stringify(integrityTokenData)}`,
            );

            const ttlMs = estimatedTtlSecs * 1000;
            const tokenMinter: TokenMinter = {
                expiry: new Date(Date.now() + ttlMs),
                integrityToken,
                minter: await WebPoMinter.create(
                    integrityTokenData,
                    webPoSignalOutput,
                ),
                used: false,
            };
            this._minterCache.set(cacheSpec.key, tokenMinter);

            const { label, ip } = cacheSpec;
            const { challengeSource, interpreterCached, serverIp } = stats;
            this.logger.log(
                `Generated POT minter for ${label} in ${elapsed(start)}: ` +
                    `challenge from ${challengeSource} in ${challengeTime} ` +
                    `(interpreter ${interpreterCached ? "cached" : "fetched"}), ` +
                    `BotGuard ${botguardTime}, GenerateIT ${integrityTokenTime}; ` +
                    `valid for ${(estimatedTtlSecs / 3600).toFixed(1)}h` +
                    (serverIp
                        ? `; YouTube sees this server as ${describeIp(serverIp)}`
                        : "") +
                    `; ${this._minterCache.size} minter(s) cached`,
            );
            if (ip && serverIp && ip !== serverIp)
                this.logger.warn(
                    `POT minter for ${describeIp(ip)} was generated from ` +
                        `${describeIp(serverIp)}: yt-dlp and this server reach ` +
                        "YouTube from different IPs, so its tokens may be rejected",
                );

            if (this.backgroundRefresh)
                this.scheduleRefresh(
                    cacheSpec,
                    potCtx,
                    innertubeContext,
                    Math.max(ttlMs - SessionManager.REFRESH_LEAD_MS, ttlMs / 2),
                );
            return tokenMinter;
        } catch (e) {
            throw new Error(`Failed to generate an integrity token.`, {
                cause: e,
            });
        }
    }

    private async tryMintPOT(
        contentBinding: string,
        tokenMinter: TokenMinter,
    ): Promise<YoutubeSessionData> {
        tokenMinter.used = true;
        try {
            const poToken =
                await tokenMinter.minter.mintAsWebsafeString(contentBinding);
            if (poToken) {
                this.logger.log(`poToken: ${poToken}`);
                const youtubeSessionData: YoutubeSessionData = {
                    contentBinding,
                    poToken,
                    expiresAt: new Date(
                        Date.now() + this.TOKEN_TTL_HOURS * 60 * 60 * 1000,
                    ),
                };
                if (this.youtubeSessionDataCaches)
                    this.youtubeSessionDataCaches[contentBinding] =
                        youtubeSessionData;
                return youtubeSessionData;
            } else throw new Error("Unexpected empty POT");
        } catch (e) {
            throw new Error(
                `Failed to mint POT for ${contentBinding}: ${e.message}`,
                { cause: e },
            );
        }
    }

    private getFetch(
        proxySpec: ProxySpec,
        maxRetries: number,
        intervalMs: number,
        timeoutMs: number,
    ): PotContext["fetch"] {
        const { logger } = this;
        return async (url: any, options: any): Promise<any> => {
            const method = (options?.method || "GET").toUpperCase();
            let target = String(url);
            try {
                const { host, pathname } = new URL(target);
                target = host + pathname; // drop the query string
            } catch {
                // keep the raw value
            }
            for (let attempts = 1; attempts <= maxRetries; attempts++) {
                const start = performance.now();
                try {
                    const axiosOpt: AxiosRequestConfig = {
                        headers: options?.headers,
                        params: options?.params,
                        httpsAgent: proxySpec.asDispatcher(logger),
                        proxy: false,
                        // axios waits forever by default, so a stalled
                        // proxy connection would hang the whole request
                        timeout: timeoutMs,
                    };
                    const response = await (method === "GET"
                        ? axios.get(url, axiosOpt)
                        : axios.post(url, options?.body, axiosOpt));
                    logger.debug(
                        `${method} ${target}: ${response.status} in ${elapsed(start)}`,
                    );

                    return {
                        ok: response.status >= 200 && response.status < 300,
                        status: response.status,
                        json: async () => response.data,
                        text: async () =>
                            typeof response.data === "string"
                                ? response.data
                                : JSON.stringify(response.data),
                    };
                } catch (e) {
                    const failure =
                        `${method} ${target} failed after ${elapsed(start)} ` +
                        `(attempt ${attempts}/${maxRetries}): ${e?.message}`;
                    if (attempts >= maxRetries) {
                        logger.warn(failure);
                        throw new Error(
                            `Error reaching ${method} ${url}: All ${attempts} retries failed.`,
                            { cause: e },
                        );
                    }
                    logger.warn(
                        `${failure}, retrying in ${intervalMs / 1000}s`,
                    );
                    await new Promise((resolve) =>
                        setTimeout(resolve, intervalMs),
                    );
                }
            }
        };
    }

    async generatePoToken(
        contentBinding: string | undefined,
        proxy: string = "",
        bypassCache = false,
        sourceAddress: string | undefined = undefined,
        disableTlsVerification: boolean = false,
        challenge: ChallengeData | undefined = undefined,
        innertubeContext?: InnertubeContext,
    ): Promise<YoutubeSessionData> {
        const start = performance.now();
        this.cleanupCaches();

        const pxySpec = new ProxySpec({
            sourceAddress,
            disableTlsVerification,
        });
        if (proxy) {
            pxySpec.proxy = proxy;
        } else {
            pxySpec.proxy =
                process.env.HTTPS_PROXY ||
                process.env.HTTP_PROXY ||
                process.env.ALL_PROXY;
        }

        const cacheSpec = new CacheSpec(
            pxySpec,
            innertubeContext?.client.remoteHost || null,
        );

        const bgFetch = this.getFetch(pxySpec, 3, 5000, 10000);
        let innertube: Innertube | undefined = undefined;
        if (!contentBinding && innertubeContext) {
            this.logger.warn(
                "No content binding provided, using the one from the supplied Innertube context...",
            );
            contentBinding = innertubeContext.client.visitorData;
        }

        if (!contentBinding) {
            this.logger.warn(
                "No content binding provided, generating visitor data via Innertube...",
            );
            const innertubeStart = performance.now();
            innertube = await Innertube.create({
                retrieve_player: false,
                fetch: bgFetch,
            });
            contentBinding = innertube.session.context.client.visitorData;
            this.logger.log(
                `Generated visitor data in ${elapsed(innertubeStart)}`,
            );
        }

        if (!contentBinding) throw new Error("Unable to generate visitor data");

        if (!innertubeContext) innertubeContext = innertube?.session.context;

        const potCtx: PotContext = {
            fetch: bgFetch,
            globalObj: globalThis,
        };

        this.logger.log(
            `POT request for ${contentBinding} from ${cacheSpec.label}` +
                (cacheSpec.ip && pxySpec.proxy
                    ? `, via proxy ${pxySpec.loggableProxy}`
                    : "") +
                (cacheSpec.ip && sourceAddress
                    ? `, from ${sourceAddress}`
                    : "") +
                (bypassCache ? ", bypassing cache" : ""),
        );

        if (!bypassCache && this.youtubeSessionDataCaches) {
            const sessionData = this.youtubeSessionDataCaches[contentBinding];
            if (sessionData) {
                this.logger.log(
                    `POT for ${contentBinding} still fresh, returning cached token`,
                );
                return sessionData;
            }
        }

        let tokenMinter = bypassCache
            ? undefined
            : this._minterCache.get(cacheSpec.key);
        let minterSource = "cached minter";
        if (!tokenMinter || new Date() >= tokenMinter.expiry) {
            minterSource = bypassCache
                ? "new minter, cache bypassed"
                : tokenMinter
                  ? "new minter, previous one expired"
                  : "new minter, none cached for this IP";
            tokenMinter = await this.generateTokenMinter(
                cacheSpec,
                potCtx,
                challenge,
                innertubeContext,
            );
        }
        const sessionData = await this.tryMintPOT(contentBinding, tokenMinter);

        const total = (performance.now() - start) / 1000;
        const summary = `Minted POT for ${contentBinding} in ${elapsed(start)} (${minterSource})`;
        if (total > PLUGIN_TIMEOUT_SECS)
            this.logger.warn(
                `${summary}, longer than the plugin's ${PLUGIN_TIMEOUT_SECS}s ` +
                    "timeout, so yt-dlp has likely given up on it",
            );
        else this.logger.log(summary);
        return sessionData;
    }
}
