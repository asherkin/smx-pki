# SourceMod SMX Signing Proposal

## Signature Section Format
```
[ u8] Signature Section Version
[ u8] No. of Certificates
-- Certificate 1
   [u32] Length of Certificate Blob
   [...] DER Encoded Certificate Blob
-- Certificate N
   ...
[ u8] Signature Type
[...] Binary Signature Blob
```

### Notes
* The `.signature` section must be outside the compressed region.
* The version number is fixed at 0 until a stable release.
* A valid signature will always have >= 1 certificate.
* The signer will always be the first certificate.
* Any other certificates provided are used to complete the chain of trust.
* The signature is calculated over the whole file with a zeroed placeholder signature.

### Signature Schemes
1. SHA256 RSASSA-PSS

### Todo
* Multiple signatures!
* Add a length before the signature blob to allow skipping unparseable certificates.

## Tools

* `root_ca_gen.php`  
  Creates an example self-signed Root CA certificate and private key.
* `user_ca_gen.php`  
  Creates an example Intermediate CA certificate (signed by the root) and private key.
* `author_gen.php`  
  Creates an example plugin author certificate (signed by the intermediate) and private key.
* `sign_plugin.php`  
  Signs plugin.smx with the example author's private key.
* `verify_plugin.php`  
  (Incomplete) Verifies the signature in the signed plugin against the author's certificate (and chain of trust).

Run these scripts in this order to test the functionality.
