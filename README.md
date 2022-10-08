# WIP, DO NOT USE

The goal here is to extend bcrypt to wrap a 256-bit secret using a key derived
from the salt and password, in minimal additional time, without opening up any
cracking shortcuts.

Current approach is to hash the final eksblowfish internal state with BLAKE2b
and use the result as a key for ChaCha20-Poly1305. Thanks to
[Sc00bz](https://github.com/Sc00bz)
for the suggestion to use `blake2b(S[])` as the key.

The motivating use case is to provide an key for use with
[Dovecot’s](https://dovecot.org/)
[mail crypt plugin](https://doc.dovecot.org/configuration_manual/mail_crypt_plugin/).
