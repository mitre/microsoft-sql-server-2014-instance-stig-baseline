| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure                         |Rony Xavier|*|*|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|Rony Xavier|*|*|
||InSpec syntax checker|Rony Xavier|*|#9#8#6#7|
||Local commands focused on target not the runner|Rony Xavier|*|*|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|Rony Xavier|*|*|
||Descriptive output for findings details|Rony Xavier|*|#5|
|Docs|Documentation quality (i.e. README)<br> novice level instructions including prerequisites|Yarick Tsagoyko|10/31/2018|n/a|
||Consistency across other profile conventions |Rony Xavier|11/2/2018|#3|
||Spelling grammar|*|*|*|
||Removing debugging documentation and code|*|*|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges|Rony Xavier|*|#2#5|
||Slowing the target (e.g. filling up disk, CPU spikes)|Rony Xavier|*|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|Rony Xavier|*|*|
||Check for “stuck” situations (e.g., profile goes on forever)|Rony Xavier|*|*|


Pausing review until general unpdates suggested in issue #5 is applied to rest of the controls
