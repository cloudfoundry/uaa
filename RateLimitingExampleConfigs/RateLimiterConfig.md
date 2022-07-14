# <a id="TOC"></a>UAA Rate Limiting

TOC:<p>
&nbsp; &nbsp;          [Enablement](#Enablement)<br>
&nbsp; &nbsp;          [Configuration file structure](#FileStruct)<br>

&nbsp; &nbsp;          [Common Root Fields (from both the local file and the URL)](#DocCommonFields)<br>
&nbsp; &nbsp;          [LimiterMap Fields](#DocLimiterMapFields)<br>

&nbsp; &nbsp;          [Logging Option Definition](#DocLOD)<br>
&nbsp; &nbsp;          [Credential ID Definition](#DocCID)<br>
&nbsp; &nbsp; &nbsp;   [JWT *parameters*](#JWTparms)<br>
&nbsp; &nbsp; &nbsp;   [JWTjsonField *parameters*](#JWTjsonFieldparms)<br>
&nbsp; &nbsp;          [Request Limit(s) Definition(s)](#DocRLD)<br>
&nbsp; &nbsp;          [Minimum and Multiple Request Limit Definition(s) rules & information](#RulesAndInfos)<br>
&nbsp; &nbsp; &nbsp;   [Rule 1: No two *Limiter Map*s can contain an identical *pathSelector*](#Rule-1)<br>
&nbsp; &nbsp; &nbsp;   [Rule 2: There must be at least one *Limiter Map*](#Rule-2)<br>
&nbsp; &nbsp; &nbsp;   [Information 1: Selection of Single or Multiple *Limiter Map*(s)](#Information-1)<br>
&nbsp; &nbsp; &nbsp;   [Information 2: Selection of Single or Multiple *Window Type*(s)](#Information-2)<br>
&nbsp; &nbsp; &nbsp;   [Information 3: Order of *Window Type* limiter(s) from Multiple *Limiter Map*s](#Information-3)<br>
&nbsp; &nbsp; &nbsp;   [Information 4: Order of *Caller IP* extraction](#Information-4)<br>

<br>
                                              
## <a id="Enablement"></a> Enablement

Rate Limiting is enabled in two ways:
1. By an environment variable "RateLimiterConfigUrl" (which acts as a source of dynamic configuration updates), that must start with either "http://" or "https://" (from an enablement perspective the rest of the URL does NOT matter).
2. By a local file "RateLimiterConfig.yml", that exists in any of the following four 'directories', checked in the following order:
   1. Environment variable "CLOUDFOUNDRY_CONFIG_PATH" (Bosh based CFs),
   2. Environment variable "UAA_CONFIG_PATH" (K8s based CFs),
   3. Environment variable "RateLimiterConfigDir",
   4. The root of the applications "resource" directory.

You can see (and use) a URL example with:
> export&nbsp;RateLimiterConfigUrl=https://raw.githubusercontent.com/litesoft/RateLimiterExampleConfig/main/RateLimiters.yaml

Obviously the local file "RateLimiterConfig.yml", is read once on startup, and assuming there are no errors, will become the initial (and default) limits.
If there is an error interpreting the local file "RateLimiterConfig.yml", the error is logged (and available at the "RateLimitingStatus" endpoint), and
Rate Limiting is semi-active -- meaning the Rate Limiting infrastructure is activated, but with no initial (or default) limits!

There is one difference between the local file "RateLimiterConfig.yml" and the environment
variable "RateLimiterConfigUrl" based file; the local file "RateLimiterConfig.yml" can 
contain one more field "dynamicConfigUrl", if present and the value starts with
"http://" or "https://", then it becomes the default source of dynamic configuration updates
(if the environment variable "RateLimiterConfigUrl" exists it supersedes the
"dynamicConfigUrl" field in the local file "RateLimiterConfig.yml").


<small>[back to TOC](#TOC)</small>

## <a id="FileStruct"></a> Configuration file structure

The file is basically a single Yaml Document (documents are delineated/separated by lines with three dashes "---");
leading empty documents are ignored (a document with comment lines is NOT ignored).

Note: the behaviour when more than one remaining document exists has not been tested.

In the final remaining single document, comment lines (lines starting with a Pound Sign "#") are allowed any place (and ignored)!.

<small>[back to TOC](#TOC)</small>

## <a id="DocCommonFields"></a> Common Fields (from both the local file and the URL sourced file)

* loggingOption - (optional) String (see [Details](#DocLOD))
* credentialID - (optional) String (see [Details](#DocCID))
* limiterMappings - List of [LimiterMap(s)](#DocLimiterMapFields)

## <a id="DocLimiterMapFields"></a> LimiterMap Fields

* name - (required) String
* global - ([optional but](#RequiredRS)) String - (see [Window Type](#WindowType))
* withCallerCredentialsID - ([optional but](#RequiredRS)) String - (see [Window Type](#WindowType))
* withCallerRemoteAddressID - ([optional but](#RequiredRS)) String - (see [Window Type](#WindowType))
* withoutCallerID - ([optional but](#RequiredRS)) String - (see [Window Type](#WindowType))
* pathSelectors - (required non-empty) List of String(s) - (see [Path Selector](#pathSelector)) 

#### <a id="RequiredRS"></a> Note - There must be at least ONE [Window Type](#WindowType) in a Limiter Map!

## <a id="DocLOD"></a> Logging Option Definition

The 'loggingOption' field looks like:
> loggingOption: AllCalls

And has three logging options:
1. OnlyLimited  (the default) - single line log entries, only requests that are limited;
lines start with "Rate Limited path" and include the Limiting Compound Key.
2. AllCalls - single line log entries, all requests; lines start with "path" (see [Note](#AllCalls))
3. AllCallsWithDetails - multi-line log entries, all requests; first line starts with
"********************************** RateLimiter w/ path" (see [Note](#WithDetails))

#### <a id="AllCalls"></a> Note - *AllCalls* includes the duration of the limiter overhead in nanoseconds:
- Limited requests include "-- LIMITED by" text AND the Limiting Compound Key. 
- Non-Limited requests include "-- NOT limited" text. 

#### <a id="WithDetails"></a> Note - reading the *AllCallsWithDetails* output should be strait forward:
- Limited requests include which internal limiter(s) were called and which was the limiting internal limiter.
- Non-Limited requests include which internal limiter(s) were called AND the requests remaining for each internal limiter -
after the current request has consumed an entry.

<small>[back to TOC](#TOC)</small>

## <a id="DocCID"></a> Credential ID Definition

The value of the 'credentialID' field has a number of variations, here is an example that extracts a
JSON based 'email' field via a 'regex' from the 'Claims' section:
> credentialID: 'JWT:Claims+"email"\s*:\s*"(.*?)"'

Note: since the above regex does not differentiate between a 'root' 'email' field and a nested 'email' field,
if you want only a 'root' field, it is better to use the 'JWTjsonField' Credential ID Definition version; for
an 'email' field it looks like:
> credentialID: 'JWTjsonField:Claims:email'

All Credential ID Definitions consist of a *key* ("JWT" or "JWTjsonField" in the above examples) and a
(sometimes optional) *parameters* section
(the text after the *key*-*parameters* separating colin ':')

Note: if there are no *parameters*, the colin is optional.

Currently, only two types of *credentialID*s are currently supported,
specifically the "JWT" and the "JWTjsonField" (shown in the above examples).

<small>[back to TOC](#TOC)</small>

### <a id="JWTparms"></a> JWT *parameters*

> credentialID: 'JWT:Claims+"email"\s*:\s*"(.*?)"'

The "JWT" *keyed*, Credential ID Definition's *parameters* are **optional**; they are:
1. *section reference* - Sections can be referenced by their
   offset/index (0, 1, or 2) or their names (see [Note](#JWT-section));
   since the regex is optional, *section reference* can be any of the 3 standard sections!
2. *Regex value extractor* - example above shows first 'email' value extractor
   to extract from the "claims" section (see [Note](#Regex-limits))

The plus sign ('+') is the separator between the *section reference* and
the *Regex value extractor* (if there is no
*Regex value extractor*, the plus sign separator is not needed).

#### <a id="Regex-limits"></a> Note (when there is a *Regex value extractor*):
- The referenced section is Base64 decoded before the *regex* is applied
  (this makes the use of regex on the Signature effectively useless).
- Both the *Header* and *Payload* sections are JSON Objects (which have
  variable *white space*), so design your regex appropriately (example uses '\s*').
- In the (light) validation of the JWT, the section selection/decoding,
  and *Regex value extractor* processing; ANY error reports that there was not a valid Credential ID!

So, a JWT *keyed* Credential ID Definition can successfully produce three kinds of (string) Credential ID:
1. Just *key* - the whole JWT token (3/4 sections still Base64 encoded with '.' separators).
2. *key*:*section* - the referenced, Base64 encoded section.
3. *key*:*section*+*regex* - whatever the regex extracts from the referenced
   Base64 decoded section. (implementation supports multiple capture groups and adds
   vertical bars '|' around and between the capture groups)

<small>[back to TOC](#TOC)</small>


### <a id="JWTjsonFieldparms"></a> JWTjsonField *parameters*

> credentialID: 'JWTjsonField:Claims:email'

The "JWTjsonField" *keyed*, Credential ID Definition's *parameters* are **required**; they are:
1. *section reference* - Sections can be referenced by their
   offset/index (0 or 1) or their names (see [Note](#JWT-section));
   since the field name is not optional, section can only be the first or second sections!
2. *Field name value extractor* - example above shows 'root' 'email' field2.

The second colin (:) is the separator between the *section reference* and
the field name.

<small>[back to TOC](#TOC)</small>

#### <a id="JWT-section"></a> Note: (certain JWTs actually have a 4th section - these are unselectable), case-insensitive text forms for 0-2 are:
0. *Header* or *Headers*
1. *Payload* or *Claims*
2. *Signature*

<small>[back to TOC](#TOC)</small>

## <a id="DocRLD"></a> Request Limit(s) Definition(s) or '*Limiter Map*'

The *Limiter Map*(s) are a YAML array under the *limiterMappings* field; each *Limiter Map* consist of at
least three (3) and no more than six (6) fields, e.g.:
> name: info<br>
> withCallerCredentialsID: 50r/s<br>
> withCallerRemoteAddressID: 50r/s<br>
> withoutCallerID: 0r/s<br>
> global: 500r/s<br>
> pathSelectors:<br>
> &nbsp; &nbsp; - "equals:/info"<br>
> &nbsp; &nbsp; - "startsWith:/info/v"<br>
> &nbsp; &nbsp; - "contains:extended info"<br>

The above example *Limiter Map* can be viewed as three subsections all of which are required:
1. "name" - every *Limiter Map* must have a *name* - this is used for two purposes: as part of the
CompoundKey AND for error reporting.
2. "pathSelectors" - every *Limiter Map* must have a *pathSelectors* field AND at least one
*pathSelector* (see [Note](#pathSelector)).
3. *Window Type*(s) - where each has *Max* requests per *N* seconds (*Max* **r/** *N* **s**) with *N* defaulting to 1,
and with a maximum of 1800 (30 mins).  A *Window Type* is effectively equivalent to an *InternalLimiter*. (see [Note 1](#WindowType) and [Note 2](#RequestsPerWindowSecs)). 

#### <a id="pathSelector"></a> Note - there are five types of *pathSelector*s (the first three require a path value be indicated after the colon):
- *equals:*/... (the path, after the colin ':', MUST start with a slash '/').
- *startsWith:*/... (the path, after the colin ':', MUST start with a slash '/').
- *contains:*... (the path, after the colin ':', MUST not be empty).
- *other*
- *all*

**Note: Since both the *other* and *all* *pathSelector*s are inherently going to handle multiple paths, the *Limiter Map* with
either of these *pathSelector*s should not have any other *pathSelector*s -- ONLY either *other* or *all*!**

#### <a id="WindowType"></a> Note 1 - there are four types of *Window Type*s (at least one MUST be present and all could be present).
They fall into two groups:<p>
- *global* - this one, if provided, will be active!  And, since *global* limiters ignore all caller identification, these limiters receive many more calls, and hence cause more mutual-exclusion (lock) contention.<br>
- non-global

non-global *Window Type*s are checked in the following order and first active STOPs the checking:
1. *withCallerCredentialsID* - this one, if provided, will be active,
IFF *Credential ID Definition* exists AND it can successfully extract the caller's *Credential ID*
2. *withCallerRemoteAddressID* - this one, if provided, will be active,
IFF the caller's IP address can be extracted (developer has never seen this not exist -- see [note](#Information-4))!
3. *withoutCallerID* - this one, if provided, will be active,
IFF the other two options were not active!

Because the *withCallerRemoteAddressID* appears to always succeed (even if it is just the last proxy),
it suggests that there is no apparent reason to also have a *withoutCallerID*.

However, if an endpoint MUST have a *Credential ID*, then the combination of the
*withCallerCredentialsID* and a "**0r/s**" *withoutCallerID* will limit
(short circuit) all calls without a *Credential ID*! 

#### <a id="RequestsPerWindowSecs"></a> Note 2 - *Window Type*'s *Max* requests per *N* seconds:
- *Max* requests can be zero '0' which means that ALL requests are blocked (for example: "withoutCallerID: 0r/s").
- A form of Burst request support can be achieved by increasing both the *Max* and *N* proportionally, e.g. you
want the calls to an endpoint from the same server to average a max of "5r/s", but are ok with a burst of 15r/s,
just change the "5r/s" to "15r/3s".
- Because bursting would probably be limited to a small multiple (e.g. 3), it is hard to understand the value
of much larger numbers for the *Window Secs*, except possibly to support (a future feature?) of an exponential
delay (e.g. like a half implementation of the "tar pit" pattern). 

<small>[back to TOC](#TOC)</small>

## <a id="RulesAndInfos"></a> Minimum and Multiple Request Limit Definition(s) rules & information

### <a id="Rule-1"></a> Rule 1: No two *Limiter Map*s can contain an identical *pathSelector*

Because the *other* and the *all* are inherently singular - *Rule 1* means that there can be at most one of each!

<small>[back to TOC](#TOC)</small>

### <a id="Rule-2"></a> Rule 2: There must be at least one *Limiter Map*

If you really don't want any limits, but want to capture all calls (using *loggingOption: AllCalls*), the best approach is to add
a *Limiter Map* with an "equals" path that is impossible to match on (note: equals is the first and fastest group to check)!

<small>[back to TOC](#TOC)</small>

### <a id="Information-1"></a> Information 1: Selection of Single or Multiple *Limiter Map*(s)

As mentioned [above](#pathSelector) there are five types of *pathSelector*s which fall into two groups:
- *all*
- non-all (path based)

As both the *all* and the non-all *Limiter Map*(s) are checked, there will likely be **One** OR **Two** *Limiter Map*(s)
selected (note: there could be ZERO -- see [Rule 2 above](#Rule-2)):
1. from *all* (selected if there is one in the Configuration file)
2. from non-all.

The "non-all" *Limiter Map* selection is the first match found in following order:
1. *equals*     (uses a map to look up the path and is very fast, best option for speed).
2. *startsWith* (uses an ordered list to find the longest matching path, linear search).
3. *contains*   (uses an ordered list to find the longest matching path, linear search).
4. *other*      (obviously if there is no *other*, and none of the above matched, then there will be no "non-all")

<small>[back to TOC](#TOC)</small>

### <a id="Information-2"></a> Information 2: Selection of Single or Multiple *Window Type*(s)

For each of the *Limiter Map*(s) selected, the *Window Type*(s) are checked to see if any apply
(possibly one from each group: *global* and non-global).

Note: If no *Window Type*(s) apply, the *Limiter Map* is ignored.

Note: The combination of a *Limiter Map* and a *Window Type* (and the caller group) makes up a
*CompoundKey* and the parts are carried and processed as an *InternalLimiter*.

Note: There is a Special Scenario - where no limiting occurs,
because all *Limiter Map*(s) were ignored -- it is predicated on not having a *Limiter Map* with a **global** *Window Type* and a **all** *pathSelector*!

Ignoring the Special Scenario, the result is, there will be between 1 and 4
*Limiter Map* & *Window Type* combinations (or *InternalLimiter*s)!

<small>[back to TOC](#TOC)</small>

### <a id="Information-3"></a> Information 3: Order of *Window Type* limiter(s) from Multiple *Limiter Map*s

If there are more than one *Limiter Map* & *Window Type* combinations, then they (the *InternalLimiter*s)
are added for processing (mutual-exclusion locking) in the following order:
1. "non-global" from the "non-all" if exists
2. "non-global" from the *all* if exists
3. *global* from the "non-all" if exists
4. *global* from the *all* if exists

The reason for the order is two-fold:
1. Since the processing of the *InternalLimiter*(s) stops as soon as one indicates that it is limiting,
and it was assumed that the "non-global" and/or the "non-all" would have lower limits,
they should be checked and (possibly) limit sooner!
2. While "non-global" and/or the "non-all" would probably have lower limits,
they would also individually participate less frequently in each request;
as such they are expected to have the least mutual-exclusion (lock) contention
(waiting for lock freeing) so they should be checked first
and holding the lock a bit longer is not as detrimental as
holding the lock longer on the others, especially *all*'s *global*!

<small>[back to TOC](#TOC)</small>

### <a id="Information-4"></a> Information 4: Order of *Caller IP* extraction

The caller IP address is extracted from **HttpServletRequest** by checking the following headers and fields of the **HttpServletRequest** in the following order:
1. Header: "X-Client-IP" (whole value)
2. Header: "X-Real-IP" (whole value)
3. Header: "X-Forwarded-For" (first value of comma separated IP addresses)
4. Method: getRemoteAddr()

<small>[back to TOC](#TOC)</small>
