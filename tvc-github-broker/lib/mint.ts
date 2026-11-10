/** MINT_JWT activity and http-authz/v1 profile wire names. */
export const ACTIVITY_TYPE = "ACTIVITY_TYPE_MINT_JWT";
export const PROFILE = "JWT_PROFILE_HTTP_AUTHZ_V1";

export type HttpAuthzV1 = {
  method: string;
  path: string;
  query: string;
  headerNames: string[];
  headerDigest: string[];
  /** Empty string: the body is not bound. */
  bodyDigest: string;
  /** User ID of the token's `sub`, without the URN prefix. */
  subject: string;
  /** Decimal seconds, 1 to 300. */
  timeToLiveSeconds: string;
  /** Decimal Unix seconds, within 24 hours of the current time. */
  issuedAt: string;
};
