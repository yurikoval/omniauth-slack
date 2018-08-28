## v2.4.0 (unreleased)
Initial release of ginjo-omniauth-slack

* Add/fix AuthHash `extra['scopes_requested']`. [wbr]

* Refactor building of AuthHash to dynamically call additional API requests if necessary, scope permitting. [wbr]

* Add potential `bots.info` call, if bots info is not included in authorization response. [wbr]

* Add option to preload all possible user/team/bot data, using threads, after initial authorization token is received. [wbr]

* Use a method-specific mutex/semaphore for each API-call method when utilizing threads. [wbr]

* Add options to include or exclude specific API calls. [wbr]

* Ensure jruby compatibility. [wbr]

* Initial support for `additional_data` option, allowing additional API calls during callback phase. [wbr]

* Add support for `redirect_uri` option (covers PR https://github.com/kmrshntr/omniauth-slack/pull/39). [wbr]

* Initial support for Workspace apps and tokens. [wbr]

* Support setting slack subdomain at runtime with `team_domain` option. [wbr]

* Add token scopes to AuthHash `credentials` hash. [wbr]

* Append AuthHash `extra['raw_info']` section with full response of all API requests. [wbr]

* Respect `skip_info` option. [wbr]

* Don't insert `NA` in empty AuthHash fields, leave them as nil. [wbr]

* Add test coverage for new functionality. [wbr]


### Additional changes logged between 2.2.0 release and ginjo fork/refactor

The specifics of these commits may or may not be relevant in the ginjo fork, but their functionality is covered in one way or another.

* Merge pull request #51 from vadim7j7/fix-redirect_uri. [Shintaro Kimura]

* Merge pull request #50 from jonhue/master. [Shintaro Kimura]

* Rubygems via SSL. [jonhue]

* Fix #46 - Bump dependency version. [jonhue]

* Merge pull request #48 from jonhue/master. [Shintaro Kimura]

* Merge pull request #44 from pwnall/expose_identity. [Shintaro Kimura]

* Expose users.identity information in omniauth_hash.extra. [Victor Costan]


