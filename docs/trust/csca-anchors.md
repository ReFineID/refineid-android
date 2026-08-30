# CSCA trust anchors

Passive authentication trusts the card for everything except the root:
the Document Signer Certificate always comes from the card's own EF.SOD
(so DSC rotations need no app update), while the CSCA anchor closing the
`DSC -> CSCA` hop must ship with the app, because a forged document can
always embed a self-consistent chain.

Anchors live under `app/src/main/assets/csca/<country>/`, one DER
certificate per file. The application installs every file under `csca/`
into the native verifier at startup; anchors are matched against a DSC
by issuer-name comparison, so anchor sets for several issuing states
coexist (Finland now, Estonia planned).

## Finland (`csca/fi`)

Source: the Finnish Country Signing Certificate Authority page of the
Police of Finland, <https://poliisi.fi/en/csca>, which publishes the
download URLs and the SHA-256 fingerprints below. Verify any update
against that page before replacing a file.

| File | Validity | SHA-256 |
| --- | --- | --- |
| `cscafin4.der` | 2020-07-16 to 2030-10-16 | `8fef17a6dce01ad6bb49f750b2eb3b0a2a695b1794dc197e098447517aed7302` |
| `cscafin5.der` | 2022-04-06 to 2032-07-06 | `3e46615533fd4f1b3e6e3fc9fe46a848042a0be09e136412892415c3fa670cf3` |
| `cscafin6.der` | 2025-05-14 to 2035-08-12 | `b321524def2921181bc387baac34aff852871a4f90f9e244d7f4b7a1c0bdab52` |

The expired 2016 and 2011 generations are deliberately not bundled;
documents signed under them predate the cards this application reads.
