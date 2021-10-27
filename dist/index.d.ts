/// <reference types="qs" />
import { JWTAuth, AuthJWT } from 'auth-jwt-core';
import { Request as ERequest, Response as EResponse, NextFunction } from 'express';
export type { AuthJWT };
export { JWTAuth };
export declare const authJWTExpress: <DataParams, JWTData, ExpandedData = JWTData>(authJWT: JWTAuth<DataParams, JWTData>, options?: {
    expandSession?: ((data: JWTData) => ExpandedData | Promise<ExpandedData>) | undefined;
    disableMiddlewareRequestVerification?: boolean | undefined;
    CSRFTokenFunctions?: {
        getCSRFTokenFromRequest?: ((req: ERequest) => string) | undefined;
        getCSRFTokenFromSession?: ((req: ERequest) => string) | undefined;
    } | undefined;
} | undefined) => (req: ERequest<import("express-serve-static-core").ParamsDictionary, any, any, import("qs").ParsedQs, Record<string, any>> & {
    authJWT: AuthJWT<any, any>;
}, res: EResponse, next: NextFunction) => Promise<EResponse<any, Record<string, any>> | undefined>;
