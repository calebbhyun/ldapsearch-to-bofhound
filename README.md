# ldapsearch-to-bofhound

Convert `ldapsearch` (LDIF) output into **BOFHound**-compatible format.

This lets you use native Linux/OpenLDAP `ldapsearch` to collect Active Directory data and feed it into **BOFHound** to generate JSON files for BloodHound ingestion.

## Collect LDAP data from a Domain Controller using `ldapsearch`

The paged-results option:

- `-E pr=10000/noprompt`  
  - enables LDAP paged results using the paged results control, so `ldapsearch` walks through all result pages automatically.   
  - Active Directory enforces a server-side limit (`MaxPageSize`, often 1000 objects per page), so paging is required to retrieve more than that.  
  - The `10000` is just the requested page size; the DC will still cap each page at its configured maximum. You can adjust this number, but increasing it above the DC limit will not increase the actual page size.

To reliably retrieve `nTSecurityDescriptor` as a low-privileged user, you need to send the **Security Descriptor Flags** control:

- OID: `1.2.840.113556.1.4.801` (`LDAP_SERVER_SD_FLAGS_OID`)   
- Flags: `7` (OWNER + GROUP + DACL, no SACL), encoded as BER and then base64 → `MAMCAQc=`.   

Without this control, Active Directory will usually omit `nTSecurityDescriptor` for accounts that are not allowed to read the SACL.

The LDIF wrapping option:

- `-o ldif-wrap=no`  
  - disables LDIF line wrapping so long base64 attributes (such as `nTSecurityDescriptor`, `dnsRecord`, `objectGUID`, etc.) are printed on a single line.   
  - This is important for this converter and for BOFHound, which both expect one attribute value per line.

Sample command:

```bash
ldapsearch -LLL \
  -E pr=10000/noprompt \
  -E '!1.2.840.113556.1.4.801=::MAMCAQc=' \
  -o ldif-wrap=no \
  -H ldap://10.0.0.1:389 \
  -x -D 'domainuser@corp.local' -w 'password' \
  -b 'DC=corp,DC=local' \
  '(objectclass=*)' * nTSecurityDescriptor \
  | tee ldapsearch_all.out
