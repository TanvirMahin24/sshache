# Vendored — do not edit here

These files are copied verbatim from `sshache-sass/packages/crypto/src` (the frozen v0.1.0
E2EE wire format). The desktop Teams module must decrypt exactly what that package encrypts, so
this is the single source of truth — edit it in `sshache-sass`, then re-copy, never patch here.

Re-sync: `cp <sass>/packages/crypto/src/{index,sodium,envelope,aead,kdf,identity,teamkey,connection,shamir}.ts src/teams/crypto/`
