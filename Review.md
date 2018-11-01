| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure                         |*|*|*|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|*|*|*|
||InSpec syntax checker|*|*|*|
||Local commands focused on target not the runner|*|*|*|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|*|*|*|
||Descriptive output for findings details|Rony Xavier|*|#5|
||Documentation quality (i.e. README)<br> novice level instructions including prerequisites|Yarick Tsagoyko|10/32/2018|n/a |
||Consistency across other profile conventions |Rony Xavier|*|#3|
||Spelling grammar|*|*|*|
||Removing debugging documentation and code|*|*|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges|Rony Xavier|*|#2#5|
||Slowing the target (e.g. filling up disk, CPU spikes)|*|*|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|*|*|*|
||Check for “stuck” situations (e.g., profile goes on forever)|*|*|*|


Pausing review until general unpdates suggested in issue #5 is applied to rest of the controls
