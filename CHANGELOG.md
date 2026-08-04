# IronBot v19.0.9

- IronPanel API delivery no longer asks for inbound in plan, trial and bulk-create flows.
- Added admin bulk config builder with target panel selection, username base + numeric range, random password length/type, duration and unlimited traffic support.
- Bulk IronPanel API orders pass the generated password to IronPanel for OpenVPN/Cisco/L2TP-style credentials.
- Custom GB purchase is hidden and blocked when the effective per-GB price is empty or 0; users can only buy defined plans.
- Keeps v19.0.8 Cisco/OpenConnect/ocserv aliases and clean Xray labels.
