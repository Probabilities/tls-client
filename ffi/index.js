import koffi from 'koffi';
import crypto from 'crypto';
import fs from 'fs';

// Modified version of https://github.com/DemonMartin/tlsClient
// Was memory leak and used more memory because of workerthreads

// #region typedefs

/**
 * @typedef {Object} TlsClientDefaultOptions
 * @property {ClientProfile} [tlsClientIdentifier='chrome_124'] - Identifier of the TLS client
 * @property {string|null} [customLibraryPath=null] - Path to the custom library file
 * @property {boolean} [retryIsEnabled=true] - If true, wrapper will retry the request based on retryStatusCodes
 * @property {number} [retryMaxCount=3] - Maximum number of retries
 * @property {number[]} [retryStatusCodes=[408, 429, 500, 502, 503, 504, 521, 522, 523, 524]] - Status codes for retries
 * @property {boolean} [catchPanics=false] - If true, panics will be caught
 * @property {certificatePinningHosts|null} [certificatePinningHosts=null] - Hosts for certificate pinning
 * @property {CustomTLSClient|null} [customTlsClient=null] - Custom TLS client
 * @property {TransportOptions|null} [transportOptions=null] - Transport options
 * @property {boolean} [followRedirects=false] - If true, redirects will be followed
 * @property {boolean} [forceHttp1=false] - If true, HTTP/1 will be forced
 * @property {string[]} [headerOrder=["host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests", "if-modified-since", "cache-control", "dnt", "content-length", "content-type", "range", "authorization", "x-real-ip", "x-forwarded-for", "x-requested-with", "x-csrf-token", "x-request-id", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "origin", "referer", "pragma", "max-forwards", "x-http-method-override", "if-unmodified-since", "if-none-match", "if-match", "if-range", "accept-datetime"]] - Order of headers
 * @property {Object|null} [defaultHeaders=Object] - default headers which will be used in every request - Default: UserAgent Chrome v124
 * @property {Object|null} [connectHeaders=null] - Headers to be used during the CONNECT request.
 * @property {boolean} [insecureSkipVerify=false] - If true, insecure verification will be skipped
 * @property {boolean} [isByteRequest=false] - If true, the request is a byte request
 * @property {boolean} [isByteResponse=false] - If true, the response is a byte response
 * @property {boolean} [isRotatingProxy=false] - If true, the proxy is rotating
 * @property {String|null} [proxyUrl=null] - URL of the proxy. Example: http://user:password@ip:port
 * @property {Cookie[]|null} [defaultCookies=null] - Cookies of the request
 * @property {boolean} [disableIPV6=false] - If true, IPV6 will be disabled
 * @property {boolean} [disableIPV4=false] - If true, IPV4 will be disabled
 * @property {null} [localAddress=null] - Local address [not Sure? Docs are not clear]
 * @property {string} [serverNameOverwrite=''] - Lookup https://bogdanfinn.gitbook.io/open-source-oasis/tls-client/client-options
 * @property {null} streamOutputBlockSize - Block size of the stream output
 * @property {null} streamOutputEOFSymbol - EOF symbol of the stream output
 * @property {null} streamOutputPath - Path of the stream output
 * @property {number} [timeoutMilliseconds=0] - Timeout in milliseconds
 * @property {number} [timeoutSeconds=60] - Timeout in seconds
 * @property {boolean} [withDebug=false] - If true, debug mode is enabled
 * @property {boolean} [withDefaultCookieJar=true] - If true, the default cookie jar is used
 * @property {boolean} [withoutCookieJar=false] - If true, the cookie jar is not used
 * @property {boolean} [withRandomTLSExtensionOrder=true] - If true, the order of TLS extensions is randomized
 */

/**
 * @typedef {Object} TlsClientOptions
 * @property {String|Object} body - Body of the request
 * @property {string} method - Method of the request
 * @property {boolean} catchPanics - If true, panics will be caught
 * @property {null} certificatePinningHosts - Hosts for certificate pinning
 * @property {null} customTlsClient - Custom TLS client
 * @property {null} transportOptions - Transport options
 * @property {boolean} followRedirects - If true, redirects will be followed
 * @property {boolean} forceHttp1 - If true, HTTP/1 will be forced
 * @property {null} headerOrder - Order of headers
 * @property {null} headers - Headers
 * @property {boolean} insecureSkipVerify - If true, insecure verification will be skipped
 * @property {boolean} isByteRequest -  When you set isByteRequest to true the request body needs to be a base64 encoded string. Useful when you want to upload images for example.
 * @property {boolean} isByteResponse - When you set isByteResponse to true the response body will be a base64 encoded string. Useful when you want to download images for example.
 * @property {boolean} isRotatingProxy - If true, the proxy is rotating
 * @property {null} proxyUrl - URL of the proxy
 * @property {null} requestBody - Body of the request
 * @property {Cookie[]|null} requestCookies - Cookies of the request
 * @property {Object|null} defaultHeaders - Default headers
 * @property {boolean} disableIPV6 - If true, IPV6 will be disabled
 * @property {null} localAddress - Local address
 * @property {String|null} sessionId - ID of the session
 * @property {string} serverNameOverwrite - Overwrite server name
 * @property {null} streamOutputBlockSize - Block size of the stream output
 * @property {null} streamOutputEOFSymbol - EOF symbol of the stream output
 * @property {null} streamOutputPath - Path of the stream output
 * @property {number} timeoutMilliseconds - Timeout in milliseconds
 * @property {number} timeoutSeconds - Timeout in seconds
 * @property {string} tlsClientIdentifier - Identifier of the TLS client
 * @property {boolean} withDebug - If true, debug mode is enabled
 * @property {boolean} withDefaultCookieJar - If true, the default cookie jar is used
 * @property {boolean} withoutCookieJar - If true, the cookie jar is not used
 * @property {boolean} withRandomTLSExtensionOrder - If true, the order of TLS extensions is randomized
 * Custom configurable options for the TLS client
 * @property {boolean} [retryIsEnabled=true] - If true, wrapper will retry the request based on retryStatusCodes
 * @property {number} [retryMaxCount=3] - Maximum number of retries
 * @property {number[]} [retryStatusCodes=[408, 429, 500, 502, 503, 504, 521, 522, 523, 524]] - Status codes for retries
*/

/**
 * @typedef {Object} TlsClientResponse
 * @property {string} sessionId - The reusable sessionId if provided on the request
 * @property {number} status - The status code of the response
 * @property {string} target - The target URL of the request
 * @property {string} body - The response body as a string, or the error message
 * @property {Object} headers - The headers of the response
 * @property {Object} cookies - The cookies of the response
 * @property {number} retryCount - The number of retries
 */

// #endregion

class TLSClient {
    /**
     * @description Create a new TlsClient
     * @param {TlsClientDefaultOptions} options 
    */
    constructor(options = {}) {
        /**
         * @type {TlsClientDefaultOptions}
        */

        this.libaryPath = options.customLibraryPath;
        if (!this.libaryPath)
            throw new Error('You are required to provide a libary path.');

        this.sessionId = crypto.randomUUID()
        this.defaultOptions = this.__build_default(options);

        this.lib = koffi.load(this.libaryPath);
        this.functions = {
            request: this.lib.func('request', 'string', ['string']),
            freeMemory: this.lib.func('freeMemory', 'void', ['string']),
            destroyAll: this.lib.func('destroyAll', 'void', []),
            destroySession: this.lib.func('destroySession', 'string', ['string']),
        }
    }

    __build_default(options = {}) {
        const defaultOptions = {
            tlsClientIdentifier: 'chrome_124',
            catchPanics: false,
            certificatePinningHosts: null,
            customTlsClient: null,
            customLibraryPath: null,
            transportOptions: null,
            followRedirects: false,
            forceHttp1: false,
            headerOrder: ["host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests", "if-modified-since", "cache-control", "dnt", "content-length", "content-type", "range", "authorization", "x-real-ip", "x-forwarded-for", "x-requested-with", "x-csrf-token", "x-request-id", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "origin", "referer", "pragma", "max-forwards", "x-http-method-override", "if-unmodified-since", "if-none-match", "if-match", "if-range", "accept-datetime"],
            defaultHeaders: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            },
            connectHeaders: null,
            insecureSkipVerify: false,
            isByteRequest: false,
            isByteResponse: false,
            isRotatingProxy: false,
            proxyUrl: null,
            defaultCookies: null,
            disableIPV6: false,
            disableIPV4: false,
            localAddress: null,
            serverNameOverwrite: '',
            streamOutputBlockSize: null,
            streamOutputEOFSymbol: null,
            streamOutputPath: null,
            timeoutMilliseconds: 0,
            timeoutSeconds: 60,
            withDebug: false,
            withDefaultCookieJar: true,
            withoutCookieJar: false,
            withRandomTLSExtensionOrder: true,
            retryIsEnabled: true,
            retryMaxCount: 3,
            retryStatusCodes: [408, 429, 500, 502, 503, 504, 521, 522, 523, 524],
            customLibraryDownloadPath: null,
            ...options
        };

        return defaultOptions;
    }

    __combine_options(options = {}) {
        const defaultHeaders = this.defaultOptions.defaultHeaders || {};
        const headers = {
            ...defaultHeaders,
            ...options.headers || {}
        }

        const defaultCookies = this.defaultOptions.defaultCookies || [];
        const requestCookies = [
            ...defaultCookies,
            ...options.requestCookies || []
        ]

        return {
            ...this.defaultOptions,
            ...options,
            headers,
            requestCookies,

            // Remove the headers and cookies from the default options
            defaultCookies: undefined,
            defaultHeaders: undefined
        }
    }

    __convert_body(body = {}) {
        if (typeof body === 'object' || Array.isArray(body)) return JSON.stringify(body);
        return body.toString();
    }

    async __free_memory(id) {
        return await this.functions.freeMemory(id);
    }

    requestAsPromise = (options) => new Promise(async (resolve) => {
        this.functions.request.async(JSON.stringify(options), (_, response) => {
            const responseObject = JSON.parse(response)

            resolve(responseObject)
        })
    })

    async sendRequest(options = {}) {
        const response = await this.requestAsPromise(options)

        await this.__free_memory(response.id);

        // Remove the id from the response | Useless for user
        delete response.id;

        return response;
    }

    async __retry_request(options = {}) {
        let retryCount = 0;
        let response;

        do {
            response = await this.sendRequest(options);
            response.retryCount = retryCount++;
        } while (options.retryIsEnabled && options.retryMaxCount > retryCount && options.retryStatusCodes.includes(response.status));

        return response;
    }

    /**
     * @description Send a request
     * @param {URL|string} url 
     * @param {TlsClientOptions} options 
     * @returns {Promise<TlsClientResponse>}
     */
    async request(url, options = {}) {
        const method = options.method || 'GET';

        const structuredOptions = {
            sessionId: this.sessionId,
            requestUrl: String(url),
            requestMethod: method,
            requestBody: options.body ? this.__convert_body(options.body) : null,
            requestCookies: [],
            ...options
        }

        const combinedOptions = this.__combine_options(structuredOptions);

        const response = await this.__retry_request(combinedOptions)

        try {
            response.body = JSON.parse(response.body)
        } catch { }

        return response;
    }
}

const getLibraryPath = () => {
    const isWindows = process.platform === 'win32';
    const isMac = process.platform === 'darwin';
    const isLinux = process.platform === 'linux';

    const extension = isWindows ? '.dll' : isMac ? '.dylib' : isLinux ? '.so' : null;

    if (!extension) {
        throw new Error('Unsupported platform');
    }

    try {
        const files = fs.readdirSync('.');
        const libraryFile = files.find(file =>
            file.startsWith('tls-client') && file.endsWith(extension)
        );

        if (!libraryFile) {
            throw new Error(`TLS client library not found. Expected file with pattern: tls-client*${extension}`);
        }

        return libraryFile;
    } catch (error) {
        throw new Error(`Failed to locate TLS client library: ${error.message}`);
    }
};

const libraryPath = gLibraryPath();

// View all available options for tls : https://bogdanfinn.gitbook.io/open-source-oasis/shared-library/payload
const client = new TLSClient({
    disableIPV6: true,
    tlsClientIdentifier: 'chrome_133',
    withRandomTLSExtensionOrder: true,
    customLibraryPath: getLibraryPath(),
    timeoutSeconds: 10,
});

const response = await client.request('https://tls.peet.ws/api/all')
console.log(response)