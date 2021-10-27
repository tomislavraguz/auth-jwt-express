"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authJWTExpress = exports.JWTAuth = void 0;
const auth_jwt_core_1 = require("auth-jwt-core");
Object.defineProperty(exports, "JWTAuth", { enumerable: true, get: function () { return auth_jwt_core_1.JWTAuth; } });
const url_1 = require("url");
const { NODE_ENV } = process.env;
function shouldMethodBeChecked(req, methods) {
    for (let i = 0; i < methods.length; i++) {
        if (methods[i] === req.method)
            return true;
    }
    return false;
}
const authJWTExpress = (authJWT, options) => {
    const { cookieConfig, CSRFProtection: { customHeader, originCheck, token } } = authJWT;
    let getCSRFTokenFromRequest = (req) => req.body["CSRFToken"];
    //@ts-ignore
    let getCSRFTokenFromSession = (req) => req.authJWT.getData().CSRFToken;
    if (options?.CSRFTokenFunctions) {
        if (options.CSRFTokenFunctions.getCSRFTokenFromRequest)
            getCSRFTokenFromRequest = options.CSRFTokenFunctions.getCSRFTokenFromRequest;
        if (options.CSRFTokenFunctions.getCSRFTokenFromSession)
            getCSRFTokenFromSession = options.CSRFTokenFunctions.getCSRFTokenFromSession;
    }
    const checkCSRF = async (req) => {
        const csrfErrors = [];
        if (customHeader && shouldMethodBeChecked(req, customHeader.methodList)) {
            if (!req.header(customHeader.headerName)) {
                csrfErrors.push(`AUTHJWT: Missing anti-csrf header:${customHeader.headerName}`);
            }
        }
        if (originCheck && NODE_ENV === "production" && shouldMethodBeChecked(req, originCheck.methodList)) {
            let originDomain = req.header("Origin");
            if (!originDomain) {
                const referer = req.header("Referer");
                if (referer) {
                    originDomain = new url_1.URL(referer).origin;
                }
            }
            if (!originDomain && !originCheck.allowWithoutDomain) {
                csrfErrors.push("AUTHJWT: Request contains no domain, if you wish to allow originless requests set property allowWithoutDomain of origin check to true");
            }
            else {
                let isAllowedDomain = false;
                for (let i = 0; i < originCheck.domains.length; i++) {
                    if (originCheck.domains[i] === originDomain) {
                        isAllowedDomain = true;
                        break;
                    }
                }
                if (!isAllowedDomain) {
                    csrfErrors.push(`AUTHJWT: Domain ${originDomain} is not in the list of allowed domains.`);
                }
            }
        }
        if (token && shouldMethodBeChecked(req, token.methodList)) {
            const requestToken = getCSRFTokenFromRequest(req);
            const sessionToken = await getCSRFTokenFromSession(req);
            if (sessionToken !== requestToken) {
                csrfErrors.push(`AUTHJWT: CSRF token missmatch.`);
            }
        }
        return csrfErrors;
    };
    return async (req, res, next) => {
        req.authJWT = {
            _memoizedData: undefined,
            getData: async (forceDataRefresh) => {
                if (req.authJWT._memoizedData !== undefined && !forceDataRefresh)
                    return req.authJWT._memoizedData;
                let data = null;
                const { Authorization } = req.cookies;
                if (Authorization) {
                    try {
                        const JWTPayload = await authJWT.verify(Authorization, forceDataRefresh);
                        data = JWTPayload.data;
                    }
                    catch (e) {
                        if (e.name === "TokenExpiredError") {
                            const { JWTPayload, JWT } = await req.authJWT.generate(e.payload.dataParams, {
                                oiat: e.payload.oiat,
                                maxAge: e.payload.maxAge
                            });
                            data = JWTPayload.data;
                        }
                        else {
                            req.authJWT.remove();
                        }
                    }
                }
                if (data && options?.expandSession) {
                    data = await options.expandSession(data);
                }
                req.authJWT._memoizedData = data;
                return req.authJWT._memoizedData;
            },
            generate: async (dataParams, JWTOptions) => {
                const { JWTPayload, JWT } = await authJWT.generate(dataParams, JWTOptions);
                let data = JWTPayload.data;
                if (options?.expandSession) {
                    data = await options.expandSession(data);
                }
                req.authJWT._memoizedData = data;
                if (cookieConfig && cookieConfig.useCookie) {
                    res.cookie('Authorization', `Bearer ${JWT}`, cookieConfig.cookieOptions);
                }
                return {
                    JWTPayload,
                    data: req.authJWT._memoizedData,
                    JWT
                };
            },
            refreshData: () => req.authJWT.getData(true),
            remove: () => {
                req.authJWT._memoizedData = null;
                res.clearCookie('Authorization');
            },
            checkCSRF: () => checkCSRF(req)
        };
        if (!options?.disableMiddlewareRequestVerification) {
            const csrfErrors = await req.authJWT.checkCSRF();
            if (csrfErrors.length) {
                if (NODE_ENV === "production") {
                    return res.sendStatus(400);
                }
                else {
                    throw Error(JSON.stringify(csrfErrors));
                }
            }
        }
        next();
    };
};
exports.authJWTExpress = authJWTExpress;
