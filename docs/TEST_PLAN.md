# Test Plan (fill "Actual" and attach screenshots in /docs/screenshots)

| # | Input | Expected | Actual | Screenshot | Pass/Fail |
|---|-------|----------|--------|-----------|-----------|
| 1 | 8.8.8.8 | Type IP, VT lookup, risk label | | | |
| 2 | 999.999.999.999 | Rejected as invalid | | | |
| 3 | example.com | Type DOMAIN | | | |
| 4 | https://example.com/login | Type URL | | | |
| 5 | d41d8cd98f00b204e9800998ecf8427e | Type MD5 | | | |
| 6 | 44d88612fea8a8f36de82e1278abb02f (EICAR MD5) | Type MD5, High risk with API key | | | |
| 7 | not a valid ioc | Rejected | | | |
| 8 | Any valid IOC, no API key | "Not assessed", no crash | | | |
| 9 | Random unseen hash | "Unknown" (VT 404) | | | |
| 10 | History page / CSV export | Entries listed, newest first | | | |
