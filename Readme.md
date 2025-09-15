####

### Notes
##### TI source files
Consolidated mock TI files into a centralized IOC list, as I would normally do for regular implementations if not querying information real time.
I would have a normalized IOC list by IOC type or provider first.

##### Enrichment
Enrichment can definitely be reduced and optimized if business rules were established.
Ex.: always use highest score from all TI proviers evaluated, always use highest risk from all providers evaluated (malicious > suspicious > clean, etc..)