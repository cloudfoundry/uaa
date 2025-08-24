# UAA Rate Limiting 
This feature allows operators to set rate limits for UAA endpoints via server configurations. As an experimental
feature, UAA rate limiting's config interface and behaviors are not considered solidified or stable. 
If you opt to be an early adopter of this feature, please pay attention to future changes in this feature 
when you upgrade UAA.

## Enablement
UAA Rate Limiting is enabled by adding a `ratelimit` section to your UAA instance's `uaa.yml` file, which is processed 
upon server startup. If there is an error interpreting the `ratelimit` section, no rate limits will be applied, 
and the error will be logged in server logs and shown by `/RateLimitingStatus` endpoint.

## Configs
Here is a brief example of the `ratelimit` section:
```yaml
ratelimit:
  loggingOption: OnlyLimited
  credentialID: 'JWTjsonField:Payload:email'
  limiterMappings:
    - name: AuthToken
      pathSelectors:
        - "equals:/oauth/token"
      withCallerRemoteAddressID: 50r/s
    - name: SCIM
      withCallerCredentialsID: 2000r/10s
      pathSelectors:
        - "startsWith:/Users"
        - "startsWith:/Groups"
    - name: EverythingElse
      global: 2000r/s
      pathSelectors:
        - "other"
```
The example configuration above would result in the following:
* Requests to the UAA token endpoint (`/oauth/token`) will be rate-limited to 50 requests per second, 
per originating IP address.
* Requests to the UAA SCIM management endpoints (endpoints that start with `/Groups` or `/Users`) will be rate-limited to 2000 requests per 10 seconds; 
this rate limit is applied to requests with JWTs (SCIM management endpoints require a JWT to access) that have the same `email` field in their payloads.
* Requests to all other UAA endpoints will be rate-limited to 2000 total requests per second; this rate limit is applied globally to the total number of requests issued by any entities.
* Requests that are rate-limited will be logged.

### Schema of `ratelimit`
| Config Field    | Type / Constraints                                                                                                                          | Options                                                                             | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| loggingOption   | String (Optional)                                                                                                                           | OnlyLimited                                                                         | Default option. Single line log entries, showing only requests that are limited. A log line includes: 1. "Rate Limited path."  2. "Limiting Compound Key" (an identifier of the rate limiting setting that applies to the request).                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|                 |                                                                                                                                             | AllCalls                                                                            | Single line log entries, showing all requests. A log line includes: 1. "path" (of the request)  2. "duration" - the time (in nanoseconds) consumed by the rate limiter to process this request. 3. "-- LIMITED by" text, for requests that are rate limited, along with the "Limiting Compound Key" (an identifier of the rate limiting setting that applies to the request). 4. "-- NOT limited" text, for requests that are not rate limited.                                                                                                                                                                                                                                                      |
|                 |                                                                                                                                             | AllCallsWithDetails                                                                 | Similar to `AllCalls` option but includes more details. Particularly, for a request that is not rate limited yet, the log shows how many requests are left before reaching the rate limit.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| credentialID    | String (Optional, but MUST be present if any "limiterMapping" contains `withCallerCredentialsID`; see "limiterMapping" documentation below) | JWT                                                                                 | Rate limit requests containing the same JWT.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|                 |                                                                                                                                             | JWT:SOME-JWT-SECTION  (example: 'JWT:Payload')                                      | Rate limit requests containing the same JWT section. valid sections of a JWT token are: `Header`, `Payload`, `Signature`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|                 |                                                                                                                                             | JWT:SOME-JWT-SECTION-INDEX  (example: 'JWT:1')                                      | Rate limit requests containing the same JWT section (specified via section index). Valid section indices of a JWT token are: 0 (aka `Header`), 1 (aka `Payload`), 2 (aka `Signature`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|                 |                                                                                                                                             | JWT:SOME-JWT-SECTION+SOME-REGEX  (example: 'JWT:Payload+"email"\s*:\s*"(.*?)"')     | Rate limit requests containing the same value extracted by some regex within a given JWT section. For example, `credentialID: 'JWT:Payload+"email"\s*:\s*"(.*?)"'` would rate limit requests containing JWTs with the same value extracted by the regex `"email"\s*:\s*"(.*?)"` from the JWT's `Payload` section.  NOTES: The referenced section is Base64 decoded before the regex is applied.  Both the `Header` and `Payload` sections are JSON Objects (which contain white spaces), so please design your regex appropriately (our example uses `\s*` to represent any number of whitespace characters).  If the regex is invalid, the rate limit based on this `credentialID` will be skipped. |
|                 |                                                                                                                                             | JWTjsonField:SOME-JWT-SECTION:SOME-FIELD  (example: 'JWTjsonField:Payload:email')   | Rate limit requests containing the same value of some field within a given JWT section. For example, `credentialID: 'JWTjsonField:Payload:email'` would rate limit requests containing JWTs with the same `email` field value within the JWT'S `Payload` section.  valid sections of a JWT token are: `Header`, `Payload`, `Signature`.                                                                                                                                                                                                                                                                                                                                                              |
|                 |                                                                                                                                             | "JWTjsonField:SOME-JWT-SECTION-INDEX:SOME-FIELD  (example: 'JWTjsonField:1:email')" | Same as "JWTjsonField:SOME-JWT-SECTION:SOME-FIELD" except the JWT section is specified via index.  Valid section indices of a JWT token are: 0 (aka `Header`), 1 (aka `Payload`), 2 (aka `Signature`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| limiterMappings | List of "limiterMapping" (Required)                                                                                                         | See "limiterMapping" documentation below                                            | `limiterMappings` is a list of "limiterMapping." Each "limiterMapping" targets a set of UAA endpoints, and specifies how these endpoints should be rate limited.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

### Schema of "limiterMapping"
| Config Field              | Type / Constraints                                                                                                                                                                                                                                                                                                              | Example                                      | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name                      | String (Required)                                                                                                                                                                                                                                                                                                               | "LoginLogoutEndpoints"                       | An operator-defined string that will become part of the "Limiting Compound Key" (an identifier of the rate limiting setting that applies to the request), which will be logged and included in the error messages of the responses to rate-limited requests. For example, for a "limiterMapping" that applies various rate limits to UAA's login and logout endpoints, you may set the "name" field as "LoginLogoutEndpoints"                                                                                                                                                                                                |
| pathSelectors             | List of "pathSelector" (Required, the list must contain at least one "pathSelector")                                                                                                                                                                                                                                            | ["equals:/oauth/token", "startsWith:/Users"] | The field specifies the set of UAA endpoints that this "limiterMapping" targets. See documentations of "pathSelector" below                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| withCallerCredentialsID   | String (Mr/Ns where "M" is the maximum limit of requests allowed, N is duration in which the limit applies, in seconds. N can be omitted, e.g.: "50r/s".) Optional (but there MUST be at least one of `withCallerCredentialsID`, `withCallerRemoteAddressID`, `withoutCallerID`, or `global` present in each "limiterMapping"). | 50r/s                                        | The maximum number of requests (issued by an entity identified via the `credentialID`) that are allowed given a period of time. For example, when we set `withCallerCredentialsID: 50r/s`, an entity identified via the `credentialID` can only issue 50 requests per second to the UAA endpoints targeted by the `pathSelectors`.  For another example, when we set `withCallerCredentialsID: 500r/10s`, an entity identified via the `credentialID` can only issue 500 requests per 10 seconds to the UAA endpoints targeted by the `pathSelectors` (compared to `50r/s`, this example tolerates "burst requests" better). |
| withCallerRemoteAddressID | same as `withCallerCredentialsID`                                                                                                                                                                                                                                                                                               | 50r/s                                        | Similar to `withCallerCredentialsID`, except this field specifies the maximum number of requests (issued by an entity identified via its IP address) that are allowed given a period of time.                                                                                                                                                                                                                                                                                                                                                                                                                                |
| withoutCallerID           | same as `withCallerCredentialsID`                                                                                                                                                                                                                                                                                               | 50r/s                                        | This limit serves as a fall-back in case `withCallerCredentialsID` limit fails to extract CredentialID or in case `withCallerRemoteAddressID` limit fails to extract IP address.                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| global                    | same as `withCallerCredentialsID`                                                                                                                                                                                                                                                                                               | 5000r/s                                      | A maximum number of requests (issued by all entities) allowed given a period of time.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

#### NOTES
* For `withCallerCredentialsID` to function, `ratelimit.credentialID` MUST be defined (see `ratelimit` documentation above). And the current "limiterMapping"'s `pathSelectors` MUST only target endpoints that require a Credential ID (aka a token); otherwise, this `withCallerCredentialsID` limit will be ignored.
* `global` limit is more resource-intensive than other limits because it creates more mutual-exclusion contention.

### Schema of "pathSelector"
| Type                 | Example               | Format / Constraints                                                                                                                                | Description                                                                                                                                       |
|----------------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| equals:SOME-PATH     | "equals:/oauth/token" | SOME-PATH must starts with a slash '/'                                                                                                              | The rate limit will apply if the request path equals SOME-PATH.                                                                                   |
| startsWith:SOME-PATH | "startsWith:/Users"   | SOME-PATH must starts with a slash '/'                                                                                                              | The rate limit will apply if the request path starts with SOME-PATH.                                                                              |
| contains:SOME-STRING | "contains:token"      | SOME-STRING must not be an empty string                                                                                                             | The rate limit will apply if the request path contains SOME-STRING.                                                                               |
| other                | "other"               | MUST only be used alone within the same `pathSelectors`, aka MUST NOT be used if the current `pathSelectors` contains any other pathSelector types. | The rate limit will apply if the request path does NOT already match with any "pathSelector" under all the other definitions of "limiterMapping." |
| all                  | "all"                 | MUST only be used alone within the same `pathSelectors`, aka MUST NOT be used if the current `pathSelectors` contains any other pathSelector types. | The rate limit will apply to all requests.                                                                                                        |

## `/RateLimitingStatus` endpoint
The current status of the Rate limiting is published via the endpoint `/RateLimitingStatus`. 
This endpoint cannot be configured with a rate limit. This endpoint displays the following information:
- `current.status`: Overall status of UAA rate limiting, with one of the following values:
    - `DISABLED`: No configuration given, rate limiting is off.
    - `ACTIVE`: Configuration successfully parsed and active.
    - `PENDING`: Configuration file could not be read successfully.
- `current.credentialIdExtractor`: Credential ID configuration that is currently used.
- `current.loggingLevel`: loggingOption that is currently used.
- `current.limiterMapping`: Number of limiters from the configuration (aka, the size of limiterMappings from the config file)
- `fromSource`: Location of the config file that is currently applied

## Error Messages
A request denied because of a rate limit will receive the "429 - Too Many Requests" Http Status Code.
In addition, an error message is returned. Depending on whether the request Accepts HTML or JSON as a response, 
the error message is either embedded in an HTML Page or included in a JSON response body as the "error" field.

Beside the static error message: `429 - Too Many Requests - Request limited by Rate Limiter configuration:`
the error also contains information about the rate-limiting setting that limited this request.
This includes the name of the limiter as well as information about whether they have hit a "global" rate limit 
or the limit was only applied to their Credential ID or IP address.

## Misc implementation details
This section contains miscellaneous info about the implementation details of this feature.
They are for UAA dev purposes only. 

### Selection of Single or Multiple *limiterMapping*(s)

There are five types of *pathSelector*s that fall into two groups:
- *all*
- non-all (path-based)

As both the *all* and the non-all *limiterMapping*(s) are checked, there will likely be **One** OR **Two** *limiterMapping*(s)
selected:
1. from *all* (selected if there is one in the Configuration file)
2. from non-all.

The "non-all" *limiterMapping* selection is the first match found in the following order:
1. *equals* — uses a map to look up the path and is quick, the best option for speed.
2. *startsWith* — uses an ordered list to find the longest matching path, linear search.
3. *contains* — uses an ordered list to find the longest matching path, linear search.
4. *other* — if there is no *other*, and none of the above matched, then there will be no "non-all"

### Order of *Window Type* limiter(s) from Multiple *limiterMapping*s

A *Window Type* is one of the following: `withCallerCredentialsID`, `withCallerRemoteAddressID`, `withoutCallerID`, `global`.

If there are more than one *limiterMapping* & *Window Type* combinations, then they (the *InternalLimiter*s)
are added for processing (mutual-exclusion locking) in the following order:
1. "non-global" from the "non-all" if exists
2. "non-global" from the *all* if exists
3. *global* from the "non-all" if exists
4. *global* from the *all* if exists

The reason for the order is two-fold:
1. Since the processing of the *InternalLimiter*(s) stops as soon as one indicates that it is limiting,
   and it was assumed that the "non-global" and/or the "non-all" would have lower limits,
   they should be checked and (possibly) limited sooner!
2. While "non-global" and/or the "non-all" would probably have lower limits,
   they would also individually participate less frequently in each request;
   as such they are expected to have the least mutual-exclusion (lock) contention
   (waiting for lock freeing) so they should be checked first, 
   and holding the lock a bit longer is not as detrimental as
   holding the lock longer on the others, especially *all*'s *global*!

### Order of *Caller IP* extraction

The caller IP address is extracted from **HttpServletRequest** by checking the following headers and fields of the **HttpServletRequest** in the following order:
1. Header: "X-Client-IP" (whole value)
2. Header: "X-Real-IP" (whole value)
3. Header: "X-Forwarded-For" (first value of comma separated IP addresses)
4. Method: getRemoteAddr()

