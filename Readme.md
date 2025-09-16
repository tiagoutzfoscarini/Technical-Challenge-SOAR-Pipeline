####

### Notes
##### TI source files
Consolidated mock TI files into a centralized IOC list, as I would normally do for regular implementations if not querying information real time.
I would have a normalized IOC list by IOC type or provider first.

##### Enrichment
Enrichment can definitely be optimized.

##### Final indicator view
I could definitely present the provider evaluations differently (ex.: ["value", "providers": [{"source":"provider", "risk":"malicious"}]]), but as first version the way it is now is fine.