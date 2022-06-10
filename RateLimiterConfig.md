# UAA Rate Limiting

<a id="TOC"></a>TOC:<p>
&nbsp; &nbsp;          [Enablement](#Enablement)<br>
&nbsp; &nbsp;          [Configuration file structure](#FileStruct)<br>
&nbsp; &nbsp;          [Request Logging Option Definition](#DocRLOD)<br>
&nbsp; &nbsp;          [Request Credential ID Definition](#DocRCID)<br>
&nbsp; &nbsp; &nbsp;   [JWT *parameters*](#JWTparms)<br>
&nbsp; &nbsp;          [Request Limit(s) Definition(s)](#DocRLD)<br>
&nbsp; &nbsp;          [Minimum and Multiple Request Limit Definition(s) rules & information](#RulesAndInfos)<br>
&nbsp; &nbsp; &nbsp;   [Rule 1: No two *Limiter Map*s can contain an identical *pathSelector*](#Rule-1)<br>
&nbsp; &nbsp; &nbsp;   [Rule 2: Every path must be covered by an *active* limiter](#Rule-2)<br>
&nbsp; &nbsp; &nbsp;   [Information 1: Selection of Single or Multiple *Limiter Map*(s)](#Information-1)<br>
&nbsp; &nbsp; &nbsp;   [Information 2: Selection of Single or Multiple *Window Type*(s)](#Information-2)<br>
&nbsp; &nbsp; &nbsp;   [Information 3: Order of *Window Type* limiter(s) from Multiple *Limiter Map*s](#Information-3)<br>

<br>
                                              
## <a id="Enablement"></a> Enablement

Rate Limiting is enabled by an environment variable
"RateLimiterConfigUrl" that must start with either "http://" or "https://"
(from an enablement perspective the rest of the URL does NOT matter).

You can see (and use) an example with:
> export&nbsp;RateLimiterConfigUrl=https://raw.githubusercontent.com/litesoft/RateLimiterExampleConfig/main/RateLimiters.yaml

<small>[back to TOC](#TOC)</small>

## <a id="FileStruct"></a> Configuration file structure

The file is made up of a number of Yaml Documents (documents are delineated/separated by line with three dashes "---").

Each Document is processed individually, and numbered 0-n (the zero document is the one
before the first line of three dashes "---").
This numbering allows the processor to report explicitly which document
has a parsing problem - this allows for much more actionable error messages.

Line comments (line starts with a Pound Sign "#") are allowed any place (and ignored).

Empty Documents (or those with just comments &/ blank lines) are counted, but ignored.

Each Yaml Document is parsed as one of three types:

- Request Logging Option Definition (optional - only one allowed)
- Request Credential ID Definition (optional - only one allowed)
- Request Limit Definition (not optional - at least one required)

While the fields are different for each of the above types, intermixing the
fields should generate an error referencing the intermixed Document!

<small>[back to TOC](#TOC)</small>

## <a id="DocRLOD"></a> Request Logging Option Definition "Yaml Document"
                                                 
This Document consists of a single field, e.g.:
> loggingOption: AllCalls

There are three logging options:
1. OnlyLimited  (the default) - single line logs, only requests that are limited;
lines start with "Rate Limited path" and include the Limiting Compound Key.
2. AllCalls - single line logs, all requests; lines start with "path" (see [Note](#AllCalls))
3. AllCallsWithDetails - multi-line logs, all requests; first line start with
"********************************** RateLimiter w/ path" (see [Note](#WithDetails))

#### <a id="AllCalls"></a> Note - *AllCalls* includes the duration of the limiter overhead in nanoseconds:
- Limited requests include "-- LIMITED by" text AND the Limiting Compound Key. 
- Non-Limited requests include "-- NOT limited" text. 

#### <a id="WithDetails"></a> Note - reading the *AllCallsWithDetails* output should be strait forward:
- Limited requests include which internal limiter(s) were called and which was the limiting internal limiter.
- Non-Limited requests include the requests remaining for all the internal limiter(s) -
after the current request has consumed an entry.

<small>[back to TOC](#TOC)</small>

## <a id="DocRCID"></a> Request Credential ID Definition "Yaml Document"

This Document consists of a single field, e.g.:
> credentialID: 'JWT:Claims+"email"\s*:\s*"(.*?)"'

All Credential ID Definition consist of a *key* ("JWT" in the above example) and an 
optional *parameters* section
(the text after the *key*-*parameters* separating colin ':';
Note: if there are no *parameters*, the colin is optional).

Currently, only one type of *credentialID* is currently supported,
specifically the "JWT" (shown in the above example).

<small>[back to TOC](#TOC)</small>

### <a id="JWTparms"></a> JWT *parameters*

The JWT *keyed* Credential ID Definition's (optional) *parameters* are:
1. JWT section reference.  Sections can be referred to by their
offset/index (0-2) (see [Note](#JWT-section))
2. Regex value extractor - example above shows email value extractor
to extract from the "claims" section (see [Note](#Regex-limits))

The plus sign ('+') is the separator between the *section reference* and
the *Regex value extractor* (if there is no
*Regex value extractor*, the plus sign separator is not needed).

#### <a id="JWT-section"></a> Note: (certain JWTs actually have a 4th section - offset/index actually support 0-9), case-insensitive text forms for 0-2 are:
0. *Header* or *Headers*
1. *Payload* or *Claims*
2. *Signature*

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

## <a id="DocRLD"></a> Request Limit(s) Definition(s) "Yaml Document"

These Document(s) (called a *Limiter Set* or *Limiter Map*) consist of at
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
3. *Window Type*(s) - where each has *M* requests per *N* seconds (*M*r/*N*s) with *N* defaulting to 1,
and with a maximum of 1800 (30 mins) (see [Note 1](#WindowType) and [Note 2](#RequestsPerWindowSecs)). 

#### <a id="pathSelector"></a> Note - there are five types of *pathSelector*s:
- *equals:*/... (the path, after the colin ':', MUST start with a slash '/').
- *startsWith:*/... (the path, after the colin ':', MUST start with a slash '/').
- *contains:*... (the path, after the colin ':', MUST not be empty).
- *other*  (no path accepted AND is NOT allowed with any other *pathSelectors* in the same *Limiter Map*)
- *all*  (no path accepted AND is NOT allowed with any other *pathSelectors* in the same *Limiter Map*)

#### <a id="WindowType"></a> Note - there are four types of *Window Type*s (at least one MUST be present and all could be present).
They fall into two groups:<p>
- *global* - this one, if provided, will be active!<br>
- non-global

non-global *Window Type*s are checked in the following order and first active STOPs the checking:
1. *withCallerCredentialsID* - this one, if provided, will be active,
IFF *Credential ID Definition* exists AND it can successfully extract the *Credential ID*
2. *withCallerRemoteAddressID* - this one, if provided, will be active,
IFF a caller IP address can be found (developer has never seen this not exists)!
3. *withoutCallerID* - this one, if provided, will be active,
IFF the other two options were not active!

Because the *withCallerRemoteAddressID* appears to always succeed (even if it is just the last proxy),
it suggests that there is no apparent reason to also have a *withoutCallerID*.

However, if an endpoint MUST have a *Credential ID*, then the combination of the
*withCallerCredentialsID* and a "**0r/s**" *withoutCallerID* will limit
(short circuit) all calls without a *Credential ID*! 

#### <a id="RequestsPerWindowSecs"></a> Notes - *Window Type*'s *M* requests per *N* seconds:
- *M* requests can be zero '0' which means that ALL requests are blocked (in the example: "withoutCallerID: 0r/s").
- A form of Burst request support can be achieved by increasing both the *M* and *N* proportionally, e.g. you
want the calls to an endpoint from the same server to average a max of "5r/s", but are ok with a burst of 15r/s,
just change the "5r/s" to "15r/3s".
- Because bursting would probably be limited to a small multiple (e.g. 3), it is hard to understand the value
of much larger numbers for the *Window Secs*, except possibly to support (future feature) of an exponential
delay (e.g. like a "tar pit"). 

<small>[back to TOC](#TOC)</small>

## <a id="RulesAndInfos"></a> Minimum and Multiple Request Limit Definition(s) rules & information

<small>[back to TOC](#TOC)</small>

### <a id="Rule-1"></a> Rule 1: No two *Limiter Map*s can contain an identical *pathSelector*

Because the *other* and the *all* must be alone - *Rule 1* means that there can be at most one of each!

<small>[back to TOC](#TOC)</small>

### <a id="Rule-2"></a> Rule 2: Every path must be covered by an *active* limiter (e.g. at least one *Window Type* within at least one *Limiter Map*)

To ensure *Rule 2*, either an *other* OR an *all* must exists with a *global* *Window Type*.

Note: if you really don't want any global limit, the *other*'s OR the *all*'s *global* *Window Type*
can support *Integer.MAX* for the requests per second!

<small>[back to TOC](#TOC)</small>

### <a id="Information-1"></a> Information 1: Selection of Single or Multiple *Limiter Map*(s)

As mentioned [above](#pathSelector) there are five types of *pathSelector*s which fall into two groups:
- *all*
- non-all (path based)

As both the *all* and the non-all *Limiter Map*(s) are checked, there could be **One** OR **Two** *Limiter Map*s selected:
1. from *all* (selected if there is one in the Configuration file)
2. from non-all.

The "non-all" *Limiter Map* selection is the first match found in following order:
1. *equals*     (uses a map to look up the path and is very fast, best option for speed).
2. *startsWith* (uses an ordered list to find the longest matching path, linear search).
3. *contains*   (uses an ordered list to find the longest matching path, linear search).
4. *other*      (obviously if there is no *other*, and none of the above matched, then there will be no "non-all")

Remember that [Rule 2](#Rule-2) says that there will exist an *all* and/or *other* with a *global* *Window Type*,
which means that there will always be at least one *Limiter Map* selected.

<small>[back to TOC](#TOC)</small>

### <a id="Information-2"></a> Information 2: Selection of Single or Multiple *Window Type*(s)

For each of the *Limiter Map*(s) selected, the *Window Type*(s) are checked to see if any apply
(possibly one from each group: *global* and non-global).

Note: If no *Window Type*(s) apply, the *Limiter Map* is ignored.

Note: The combination of a *Limiter Map* and a *Window Type* (and the caller group) makes up a
*CompoundKey* and the parts are carried and processed as an *InternalLimiter*.

Note: There is a Special Scenario - where no limiting occurs,
because all *Limiter Map*(s) were ignored -- it is predicated on not having a *global* in an *all*!

The result is (ignoring the Special Scenario) where there will be between 1 and 4
*Limiter Map* & *Window Type* combinations (or *InternalLimiter*s)!

<small>[back to TOC](#TOC)</small>

### <a id="Information-3"></a> Information 3: Order of *Window Type* limiter(s) from Multiple *Limiter Map*s

If there are more than one *Limiter Map* & *Window Type* combinations, then they (the *InternalLimiter*s)
are added for processing (mutual-exclusion locking) in the following order:
1. "non-global" from the "non-all" if exists
2. "non-global" from the *all* if exists
3. *global* from the "non-all" if exists
4. *global* from the *all* if exists

The reason for the order is twofold:
1. Since the processing of the *InternalLimiter*(s) stops as soon as one indicates that it is limiting,
and it was assumed that the "non-global" and/or the "non-all" would have lower limits,
they would be checked and limit sooner!
2. While "non-global" and/or the "non-all" would probably have lower limits,
they would also individually participate less frequently in each request;
as such they are expected to have the least mutual-exclusion contention
(waiting for lock freeing) so they should be checked first
and holding the lock a bit longer is not as detrimental as
holding the lock longer on the others, especially *all*'s *global*!

<small>[back to TOC](#TOC)</small>
