An implementation of a secure password authentication system designed for end-to-end encrypted applications that features
- **Multi-factor authentication**. Users can configure many different extra factors of authentication and policies surrounding those extra factors,
  including code-based methods like TOTP, hardware keys performing cryptographic signatures, recovery tokens, and "remember my device" usability features.
  Moreover, the extra factors help secure the negotiated session and user keys so that even an attacker with knowledge of the user's password cannot
  decrypt their data.
- **Offline password stretching**. The server can add extra layers of hashing to existing passwords, making them more secure against offline dictionary attacks,
  all without any intervention from the user. Even users who have not logged in for a long time can be kept secure relative to the ever-growing hash power
  available to password crackers. This password stretching does not require changing the user keys or re-encrypting application data, yet it does provice extra
  security for those keys.
- **User key derivation**. Through the process of authentication, the client derives a secret key from their password that is unknown to everybody else, including
  the server. This only requires a single password for both authentication and key derivation.
- **Forward secret session key negotiation**. As part of the authentication process, a shared key is negotiated between the server and client that can be used to
  protect communications with no need for any public key infrastructure in a way that remains secure even if the user's password is later exposed.
- **Server relief**. The majority of the computational work of the protocol is performed by the client, not the server, making it significantly cheaper and easier
  to scale up to many users.
- **Two-way authentication**. Not only does a user authenticate to a server, but also the server proves to the user that they are talking to the correct server,
  not some malicious actor. This means that we no longer need to rely on the certificate authority system for security.
- **Man-in-the-middle security**. The protocol is secure not just against attackers who eavesdrop on the authentication process, but also against attackers that
  actively intervene in an authentication run, modifying, dropping, and changing messages.
- **Precomputation security**. The password is hashed together with a value never shown to the client, so any password hashes that an attacker performs prior
  to a server breach do not help them perform an offline dictionary attack at all. If server breaches are noticed promptly, then appropriate actions can be
  reliably taken before an attacker successfully cracks all but the most insecure passwords, since essentially all cracking work must be done after the breach.
- **Key compromise security**. The user and session keys are derived from mixing the password with data known only be the server and (in the session key case)
  ephemeral data, so even if an attacker acquires those keys, they still are unable to run an offline dictionary attack on the user's password. This can decrease
  the risk of password reuse.

I believe these security properties to be provably valid, but at the moment I have only written up proof sketches and have not had them independently verified.
However, none of the underlying constructions are new cryptography, and all of them have been proven secure. The security of the composition is either proven
to be secure or can easily be shown under the random oracle model to at least not damage security.

# Threat Model

TODO: Figure out exactly how much more security we can provide for 2FA. It depends on the type of 2FA.

Informally, this protocol promises three things:
- Your password will remain secret, even if everything relying on this protocol is broken and all your encryption keys are exposed.
- Without knowing your password, interacting with this protocol won't give an attacker any information useful to decrypt your data or communications.
- Without simultaneously knowing your password and having your second factor, an attacker will be unable to log in as you.
This should hold even in the face of a far-future post-quantum-computing attacker than is looking back on old, finished runs of the protocol.

TODO: This model shares a lot with the UC (Universal Composability) framework. Reframe in fully in terms of that and clear up the relationship to existing security definitions.

Formally, we consider a probabilistic polynomial time adversary interacting with a set of servers with distinct instance strings and a set of users, each of which
has a fixed password drawn from a known distribution that they reuse on all servers. (TODO: Most existing cryptanalysis seems to work in the setting of passwords
drawn from a known uniform distribution, so previously published proofs might only work in that restricted setting. However, this is unlikely to matter in practice.)
For simplicity, all hash functions are modeled under the random oracle model (ROM), and all groups and modeled under the generic group model (GGM). (TODO: Come up
tighter reductions by using the standard model.) We allow adversaries to query these hash functions and group operations an arbitrary number of times, and also provide
a translation oracle between different groups when they are the same size to model the practical choice of instantiating all of the groups with the same concrete group.
To simulate post-quantum adversaries, we sometimes allow a limited number of queries to a discrete logarithm oracle. In addition, we allow the following interactions
between the adversary an its environment:
- `Eavesdrop(user, server)` performs a successful authentication between the user and the server and returns the transcript as well as a session ID that can be passed to `ExposeSession`.
- `ConnectServer(server, first_round_input)` performs the first round of authentication between the server and the adversary, with the adversary sending arbitrary
  input. It returns the server's response as well as a session ID that can be used to perform the second round of authentication.
- `CompleteServer(server_session_id, second_round_input)` performs the second round of authentication between the server and the adversary, with the adversary
  sending arbitary input. If the `session_id` is ever reused, this call will fail. It returns the server's response.
- `ConnectClient(user, server)` returns the user's first round of information attempting to authenticate to the given server, as well as a first round ID usable to
  continue the authentication protocol with the client in the second round.
- `CompleteClient(user_session_id, first_round_response)` returns the adversary's response to the client it previously connected with and returns the user's
  input the the second round of the protocol. If the `session_id` is ever reused, this call will fail.
- `ExposeVerifier(user, server)` returns the server-side information that is persistently stored pertaining to a user.
- `ExposeSession(session_id)` returns the negotiated session key from an authentication session that was completed through `Eavesdrop`, `CompleteClient`, or `CompleteServer`. In
  the latter two cases, it returns what the non-adversarial party thinks the session key is.
- `ExposePassword(user)` returns a user's password.
- `ExposeUserKey(user, server)` returns the user key for the given user and server.
In addition, the adversary knows the set of usernames each user is registered to each server under.

An adversary with `g` guesses is said to have won this security game if it returns a user such that at most `g` times,
- the adversary called `ConnectServer` to a server with a `first_round_input` containing a username for the returned user on that server, or
- the adversary called the `PBKDF` oracle after having called `ExposeVerifier` on the returned user and some server,
and in addition the adversary returns any of the following:
- A session id that never had `ExposeSession` called on it, referring to a session that involved the user (either directly in `Eavesdrop` or `ConnectClient` or indirectly by sending the user's username in the `first_round_input` of `ConnectServer`).
- The user's password, if `ExposePassword` was never called on the user.
- A server and the user key for that user-server pair, if the adversary never called `ExposePassword` on the user and never called `ExposeUserKey` on the user-server pair.

We define a brute force adversary to be any non-adaptive adversary that first calls `ExposeVerifier` on some number of user-server pairs, then repeatedly chooses a password and user and checks the password by either
- Calling `ConnectServer` and `CompleteServer` with an honest implementation of the client side of the protocol,
- Calling `ConnectClient` and `CompleteClient` with an honest implementation of the server side of the protocol and verifier information derived from the password,
- Calling `PBKDF` on the password and information gleaned from the result of an earlier `ExposeVerifier` call to check if the hashed password matches the verifier

We claim that there does not exist any probabilistic polynomical time adversary that can win the game with `g` guesses whose probability of success is more than negligably larger than the best brute force adversary supplied with `g` guesses in the following cases:
- (Pre-quantum man-in-the-middle attacker) The adversary cannot query the discrete logarithm oracle, but can query all other oracles and perform all interactions.
- (Post-quantum eavesdropper) The adversary is allowed to query the discrete logarithm oracle but is not allowed to call `ConnectServer` or `ConnectClient`.

TODO: It seems likely that this protocol con provide some sort of limited post-quantum man-in-the-middle security, at least in the Elligator Edition/PAK variant, where the adversary would be required
to perform a new presumably expensive discrete logarithm query for every password guess. Formalize this property and prove it. See also "Generic Hardness of the Multiple Discrete Logarithm Problem" by
Aaram Yun.

## Argument for Security

A proof of password and session key security should essentially follow as the composition of proofs given in three papers,
- "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks", section 4, by Stanislaw Jarecki, Hugo Krawczyk, and Jiayu Xu,
- "Highly-Efficient and Composable Password-Protected Secret Sharing (Or: How to Protect Your Bitcoin Wallet Online)", section 3, by Stanislaw Jarecki, Aggelos Kiayias, Hugo Krawczyk, and Jiayu Xu,
- and "Simple Password-Based Encrypted Key Exchange Protocols" by Michel Abdalla and David Pointcheval,
which prove the security of compoosing a secure aPAKE with an OPRF, the security of the OPRF we use, and the security of the PAKE we use, respectively. Due to the random oracle assumption, adding
extra parameters to the final key derivation step cannot harm security. Session key security implies secrecy of the salt for the user key, since it is wrapped in a strong authenticated encryption
algorithm and will never be revealed (`ExposeSession` only returns `K_session`, not `K_serverauth`), and so using the random oracle assumption again, revealing the user key can also not harm the
password security. Proving that the user key remains secret is less directly compositional, but should follow from the fact that it is derived from an independently chosen output of the password hashing
function, so revealing any other components of the protocol besides the password cannot reveal information.

Note that the third referenced paper only proves the security of SPAKE2, not its asymmetric/augmented version, SPAKE2+. In general, I struggled to find good originating sources discussing specifically SPAKE2+,
thought its security seems generally accepted. See also "the crypto book" ("A Graduate Course in Applied Cryptography", section III.21.11.6, by Dan Boneh and Victor Shoup) for some information.

See also https://moderncrypto.org/mail-archive/curves/2015/000424.html with the quote "SPAKE2-EE's advantage is that it's slightly tidier than SPAKE2 proper, because it removes the static-DH assumption."
for information about the Elligator Edition. This also describes the application to augmentation/asymmetrization.

# Cryptographic Design

In summary, we do
- a [Ford-Kaliski password hardening](https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.17.9502) ([doi](https://doi.org/10.1109/ENABL.2000.883724)) step built with a
  [2HashDH oblivious pseudorandom function (OPRF)](https://eprint.iacr.org/2016/144) ([doi](https://doi.org/10.1109/EuroSP.2016.30)), leading into
- [SPAKE2+](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf#%5B%7B%22num%22%3A8949%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C72%2C720%2Cnull%5D)
  with explicit key confirmation, with
- two-factor authentication folded into the session (and confirmation) keys, and
- an extra user key generated from the hashed password and a server-provided salt which is only available once authentication is complete

I hope to replace SPAKE2 with its [Elligator Edition](https://moderncrypto.org/mail-archive/curves/2015/000424.html), since this is a bit more efficient, has a
cleaner security proof, and has greater resistance to partial cryptographic breaks (i.e. if discrete logarithm computations are feasible but still slow). However,
SPAKE2-EE [seems to be equivalent](https://www.ietf.org/mail-archive/web/cfrg/current/msg08851.html) to an elliptic-curve instantiation of
[PAK](https://www.iacr.org/archive/eurocrypt2000/1807/18070157-new.pdf) ([doi](https://doi.org/10.1007/3-540-45539-6_12)), which
[is covered by patents](https://datatracker.ietf.org/ipr/1283/). These may fully expire in 2020 or 2023, but further legal investigation is necessary. Alternatively,
since the augmented PAKE is largely pluggable, other schemes such as those proposed for CFRG standardization could be used. In particular, AuCPace looks promising.
Since these designs tend to use the essentially the same verifier value (a base point scaled by the password), it should be possible to upgrade protocols without
a major version change.

In this specific instantiation, we use the [`ristretto255` group](https://ristretto.group/) for both the OPRF and the PAKE, [Argon2](https://github.com/P-H-C/phc-winner-argon2)
for deriving the output of the OPRF and (with greatly reduced parameters) the session key, and [BLAKE2b](https://blake2.net/) for other hashing.

## Versioning

Although the protocol currently has only one version, it is built to be easily and securely upgraded. Versions consist of two parts. A major version number indicates
changes to the protocol that require rehashing passwords, such as changing the password hashing function or the OPRF scheme. A minor version number
indicates changes to the protocol that can be uniformly applied to all users without the involvement of users, such as changing the symmetric
portion of the PAKE.

The expected use case of this protocol is one in which the client and server are tightly synchronized and there is no flexibility for version negotiation.
However, in acknowledgement of the fact that protocols inevitably grow and this strict behavior is not always desired, we leave room in the protocol to prevent
downgrade attacks. Minor version numbers are always even, with the low bit used as a downgrade canary. Whenever sending a version specification with a minor version number
lower than the highest supported minor version, a client or server must set the low bit. When receiving a version specification, a client or server that sees a low bit
set on any minor version that is not the highest supported must reject the connection. For example, if a client or server supports protocol versions `0.0`, `0.2`, and `0.4`,
then it must only advertise support for versions `0.1`, `0.3`, and `0.4`, and it must only accept connections with advertised versions `0.0`, `0.2`, `0.4`, and `0.5`.

The major version number needs no such protection since the agreed-upon version is uniquely determined by whatever is stored in a user's record in the server database, and
so there can be no flexible version negotiation.

## PAKE

### Parameters and Notation
`instance_string` is an identifying string unique to this deployment of the protocol, such as the domain name of where the user is registered

`G_OPRF` and `G_PAKE` are prime-order cyclic groups where discrete logarithms are hard. `G`, `M_client`, and `M_server` are nothing-up-my-sleeve points in `G_PAKE`
for whom the discrete logarithm between any pair is unknown.

`H_OPRF`, `H_session`, `H_client`, and `PBKDF` are key derivation functions, and `PBKDF` is expensive to compute. They have the following signatures:
- `H_OPRF: string, string -> G_OPRF`
- `H_session: string, string, string, ℤ_|G_PAKE|, G_PAKE, G_PAKE, G_PAKE, G_PAKE, string, string, string -> string, string, string`
- `H_user: string, string -> string`
- `PBKDF: G_OPRF, string, string -> string, ℤ_|G_PAKE|, ℤ_|G_PAKE|`

`AuthEnc` and `AuthDec` are paired authenticated encryption/decryption functions with associated data.

We write groups additively, use lowercase for scalars and uppercase for group points, and write scalar-point multiplication with a space. We write `x <$- S` to denote
that `x` is chosen uniformly randomly from the set `S`.

### Protocol Diagram
```
Client                                                   Server
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
version_major <- expected major version for user (optimistically maximum supported, or whatever the server previously rejected with)
version_minor <- maximum supported minor version for version_major, or whatever the server previously rejected with changed to have the low bit set
username <- get username from user
pwd <- get password from user
P = H_OPRF(pwd, instance_string, version_major)
r <$- ℤ_|G_OPRF|
P* = r P
version_major, version_minor, username, P*     ---->
                                                         check that version_major matches authentication version for username
                                                         check that version_minor is supported
                                                         y <$- ℤ_|G_PAKE|
                                                         Y = y G
                                                         k <- lookup authentication salt for username
                                                         bpwd_shared <- lookup password (shared part)
                                                         tf_spec <- lookup user two-factor authentication preferences
                                                         Y* = Y + bpwd_shared M_server
                                               <----     k P*, Y*, tf_spec
check that version is what we were expecting
k P = r^-1 (k P*)
bpwd_client, bpwd_shared, bpwd_augment = PBKDF(k P, version_major, pwd)
x <$- ℤ_|G_PAKE|
X = x G
X* = X + bpwd_shared M_client
Y = Y* - bpwd_shared M_shared
E_shared = x Y
E_augment = bpwd_augment Y
tf_desc, tf_code <- get two factor code from user
K_session, K_salt, K_clientauth, K_serverauth = H_session(version_major, version_minor, username, bpwd_shared, X*, Y*, E_shared, E_augment, tf_spec, tf_desc, tf_code) 
X*, tf_desc, K_clientauth                      ---->
                                                         X = X* - bpwd_shared M_client
                                                         E_shared = y X
                                                         B_augment <- lookup password (verifier part)
                                                         E_augment = y B_augment
                                                         check that tf_desc is acceptable for the user
                                                         tf_code <- lookup current code for user with description tf_desc (possibly one of many, repeating the following steps for each valid)
                                                         K_session, K_clientauth, K_serverauth = H_session(version_major, version_minor, username, bpwd_shared, X*, Y*, E_shared, E_augment, tf_spec, tf_desc, tf_code)
                                                         check that the K_clientauth pieces match (try all matching tf_codes until they do)
                                                         salt <- lookup client-use salt
                                                         salt* = AuthEnc(K_salt, K_serverauth, salt)
                                               <----     salt*
salt = AuthDec(K_salt, K_serverauth, salt*)
K_user = H_user(bpwd_client, salt)

                     <----------- Communicate using K_session ------------>
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

## 2nd Factor Design

The second factor of authentication is communicated in 3 variables:
- `tf_spec` is a specification of what type of second factor is expected. This could be, for example,
  - `none`, indicating that the user does not have a second factor set up.
  - `code`, indicating that there is some sort of external code that the user must enter. If the code is available via
    a push based mechanism (e.g. email, SMS, etc.) then this might also include a description of where the code was sent.
  - `sign`, along with some challenge message that should be signed by a known public key. See below for further details.
  - an external authentication service such as through OpenID.
  - some complex specification with thresholds, ANDs, ORs, or other ways to combine multiple factors.
- `tf_desc` is a description of the type and identity of code that the user entered. For example, this can be used to distinguish
  between several available hardware keys, or between different pre-authorized devices, or different recovery codes. More generally,
  this can be used for any authentication information that the server cannot also come up with.
- `tf_code` is the part of the second factor authentication that can be symmetrically calculated on the server. This may be, for example,
  a shared code or a negotiated shared key.

### Generic instantiation

Any second factor design can be ported to this framework by simply not using `tf_code` at all: the user simply sends whatever
second factor they wish in `tf_desc`, and the server verifies that factor. This provides login security but no phishing or encryption security:
an eavesdropper with knowledge of the password but not the second factor can still extract `K_client`, and a phishing website can easily extract
and replay the second factor.

### Code-based second factors (TOTP, HOTP, and push-based methods including SMS, voice, and email): the simple approach

The most straightforward application of this system is for second factors where some code is shared between the server and the client, whether through
out-of-band communication or synchronized key schedules. In this case, `tf_desc` goes unused, while `tf_code` contains the whole code. To accommodate
slightly unsynchronized schedules, the server can just check `K_clientauth` against multiple possible codes.

However, this allowance for slack is also somewhat of a liability. Due to the small space of possible codes (only 1000000 in common systems), this
instantiation does not provide much meaningful security against phishing by a malicious server with knowledge of the user's password. Upon receiving
`K_clientauth`, they can simply brute-force search for the correct code, then send that correct code to the real server. This can be somewhat mitigated
by making `H_session` a somewhat expensive function to compute (though significantly less expensive than `PBKDF`), which makes the brute force difficult
to pull off. However, it is far from complete protection. If this is a concern, it is likely preferable to use a PAKE-based approach (see below).

### Code-based second factors: the PAKE approach

To avoid the phishing dangers of short codes, we can require that the server commit to its guesses for the code before receiving proof of knowledge of
the code from the client. Since the client can see exactly how many guesses the server makes, a malicious server is unable to determine the user's
actual code (except with low probability) because they are unable to do a brute force search. Specifically, using a two-round PAKE where the initiator
learns of success first, the server begins several parallel PAKE sessions and encodes all of the initiation messages into `tf_spec`. The client responds
in `tf_desc`, and calculates a version of `K_session`, `K_clientauth`, and `K_serverauth` including the derived key for each PAKE as `tf_code`. The
server then tries to complete each PAKE, picking the one value that correctly matches the `K_clientauth` sent by the client, and finishes the protocol
using the corresponding `K_serverauth`.

Explicitly played out using SPAKE2 and 3 guesses, the following are the modifications to the main protocol. Note that 5 guesses is common with TOTP.

```
Client                                                                    Server
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                          code_1, code_2, code_3 <- choose 3 codes that will be accepted
                                                                          y_1, y_2, y_3 <$- ℤ_|G_PAKE|
                                                                          Y_1 = y_1 G
                                                                          Y_1* = Y_1 + code_1 M_server
                                                                          Y_2 = y_2 G
                                                                          Y_2* = Y_2 + code_2 M_server
                                                                          Y_3 = y_3 G
                                                                          Y_3* = Y_3 + code_3 M_server
                                                                          tf_spec = Y_1*, Y_2*, Y_3*
                                                                          ... rest of server setup ...
                                                                <----     k P*, Y*, tf_spec
code <- ask user for code
x_1, x_2, x_3 <$- ℤ_|G_PAKE|
X_1 = x_1 G
X_1* = X_1 + code M_client
Y_1 = Y_1* - code M_server
tf_code_1 = ("1", x_1 Y_1)
X_2 = x_2 G
X_2* = X_2 + code M_client
Y_2 = Y_2* - code M_server
tf_code_2 = ("2", x_2 Y_2)
X_3 = x_3 G
X_3* = X_3 + code M_client
Y_3 = Y_3* - code M_server
tf_code_3 = ("3", x_3 Y_3)
tf_desc = X_1*, X_2*, X_3*
... rest of client authentication ...
K_session_1, K_clientauth_1, K_serverauth_1 = H_session(version_major, version_minor, username, bpwd_shared, X*, Y*, E_shared, E_augment, tf_spec, tf_desc, tf_code_1)
K_session_2, K_clientauth_2, K_serverauth_2 = H_session(version_major, version_minor, username, bpwd_shared, X*, Y*, E_shared, E_augment, tf_spec, tf_desc, tf_code_2)
K_session_3, K_clientauth_3, K_serverauth_3 = H_session(version_major, version_minor, username, bpwd_shared, X*, Y*, E_shared, E_augment, tf_spec, tf_desc, tf_code_3)
X*, tf_desc, K_clientauth_1, K_clientauth_2, K_clientauth_3     ---->
                                                                          X_1 = X_1* - code_1 M_client
                                                                          X_2 = X_2* - code_2 M_client
                                                                          X_3 = X_3* - code_3 M_client
                                                                          If tf_code = ("1", y_1 X_1) matches K_clientauth_1,
                                                                            then K_session = K_session_1 and K_serverauth = K_serverauth_1
                                                                          If tf_code = ("2", y_2 X_2) matches K_clientauth_2,
                                                                            then K_session = K_session_2 and K_serverauth = K_serverauth_2
                                                                          If tf_code = ("3", y_3 X_3) matches K_clientauth_3,
                                                                            then K_session = K_session_3 and K_serverauth = K_serverauth_3
                                                                          ... rest of server authentication ...
```

This is considerably more expensive in terms of complexity, runtime, and communication. However, the runtime is still dominated by the
password hashing, and the communication, though larger by a significant factor, is still small in an absolute sense.

TODO: Consider if there exists any way to compress the parallel PAKE sessions into one conglomerate ring-PAKE.

TODO: Look into Webauthn and the standardization process surrounding it. See if a PAKE approach to two-factor authentication can get accepted and
implemented in browsers, re-allowing the use of TOTP for two-factor authentication without the phishing problems.

### Schnorr signature challenge-response keys

One of the more modern and secure implementations of second factors involves the server submitting a challenge message to the security module and the
security module signing that message with a key known to the server. This doesn't require the server to know enough information to authenticate, limiting
the effect of server breaches, and it can easily be used to avoid phishing if the module will sign a different message depending on which server it is
authenticating to. If the underlying signature algorithm is Schnorr-based, then we can incorporate the signature into `tf_code`, helping to secure
`K_client`.

To do so, we transform the Schnorr signature into the related Exponential Challenge Response (XCR) signature [used in the HMQV key exchange](https://www.iacr.org/cryptodb/archive/2005/CRYPTO/1497/1497.pdf).
This simply replaces the scalar component of a Schnorr signature with a server-provided point multiplied by that scalar. This Diffie-Hellman-like transformation
turns the signature into an (one-way) authenticated key agreement scheme, which allows a key confirmation step to be done in conjunction with the PAKE
by hashing both keys together. Note that it is useful for the signed message (`m` in the below) to not be reused, or else leakage of the scalar Schnorr signature
component (`s` in the below) could lead to replay attacks. A convenient way to ensure this is to include the server challenge (`D` in the below) into the
message being signed as in the FXCR variant, but this may not always be possible with all challenge-response keys. However, it is unlikely that there is a
desirable challenge-response key without some way to avoid replays.

Specifically, the modified parts of the protocol are as follows, where the signing key is `Q = q G`.

```
Signer                             Client                                            Server
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                     d <$- ℤ_|G_signature|
                                                                                     D = d G
                                                                                     m <$- space of messages
                                                                                     tf_spec = (D, m)
                                                                                     ... rest of server setup ...
                                                                           <----     k P*, Y*, tf_spec
                         <----     m
r <$- ℤ_|G_signature|
R = r G
e = H(R, m)
s = r + q e
R, s                     ---->
                                   tf_desc = R
                                   tf_code = s D
                                   ... rest of client authentication ...
                                   X*, tf_desc, K_clientauth               ---->
                                                                                     R = tf_desc
                                                                                     e = H(R, m)
                                                                                     tf_code = d (R + e Q)
                                                                                     ... rest of server authentication ...
```

As shown in the HMQV paper, the security of this scheme only relies on the computational Diffie-Hellman assumption.

TODO: This protocol does not require sending the signer's public key over the wire. Investigate if this provides any meaningful two-way authentication,
with the server proving knowledge of the public key. If so, see if existing standards (e.g. Webauthn) allow for hiding of the public key.

TODO: Consider if the ephemeral challenge sent by the server can be the same as the ephemeral challenge used in the PAKE. This complicates security arguments, but would simplify
the computations and decrease network traffic a little. It probably isn't necessary.

### ECDSA challenge-response keys

The similarity of ECDSA and Schnorr makes it tempting to try the same transformation on ECDSA signatures, multiplying the scalar component by a server-provided
point. However, this falls apart, primarily because the verification algorithm for ECDSA relates two signer-chosen points instead of one point to a predefined
generator. If the base of the discrete logarithm were fixed, then we would be able to use the Knowledge-of-Exponent Assumption to show that the client must
have known the scalar part of the signature, but even ignoring the fact that KEA is a nonstandard and difficult-to-falsify assumption, it relies on the generator
being given to the adversary, not the other way around. Instead, we express the ECDSA signature as a discrete logarithm, then use the above construction with XCR
to negotiate a key.

TODO: Schnorr with all appropriate parameters (including base and public key) included in the hash is definitely secure with an adversarially chosen base, since
it is still a proper Fiat-Shamir transformation. The proof of security for XCR, however, seems to be written with a base implicitly specified for the group. Verify that
the proof still works with a variable base. This seems likely, since two calls to a CDH oracle with a consistent but adversarial base can be used to compute a
CDH with respect to a different base.

Note that because the server must know the correct generator to use when generating its challenge point, this requires an extra round of communication.
Additionally, since ECDSA signatures typically only contain the x-coordinate (or a reduced version of it) of their random point, the full point must be
recovered as part of the verification process, which must be done on the client side since we are not sending an actual signature.

Specifically, the modified parts of the protocol are as follows, where the signing key is `Q = q G`.

```
Signer                                               Client                                            Server
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                                       m <$- space of messages
                                                                                                       tf_spec = (Q, m)
                                                                                                       ... rest of server setup ...
                                                                                             <----     k P*, Y*, tf_spec
                                           <----     m
k <$- ℤ_|G_signature|
x_1 = x-coordinate of k G
r = x_1 mod |G_signature|
e = H1(m)
s = ((e + q r) / k) mod |G_signature|
r, s                                       ---->
                                                     e = H1(m)
                                                     Q' = e G + r Q
                                                     G' = (1 / s) Q'
                                                     G'                                      ---->
                                                                                                       d <$- ℤ_|G_signature|
                                                                                                       D = d G'
                                                                                             <----     D
                                                     r' <- ℤ_|G_signature|
                                                     R' = r' G'
                                                     e' = H2(G', Q', R', D, m)
                                                     s' = r' + s e'
                                                     tf_desc = R'
                                                     tf_code = s' D
                                                     ... rest of client authentication ...
                                                     X*, tf_desc, K_clientauth                        ---->
                                                                                                       x_1 = x-coordinate of G'
                                                                                                       r = x_1 mod |G_signature|
                                                                                                       e = H1(m)
                                                                                                       Q' = e G + r Q
                                                                                                       R' = tf_desc
                                                                                                       e' = H2(G', Q', R', D, m)
                                                                                                       tf_code = d (R' + e' Q')
                                                                                                       ... rest of server authentication ...
```

TODO: Is there a way to remove the extra round of communication?

### Remembered Devices

The context of a "Remember this Device" feature is particularly flexible, since the algorithm used and data stored is essentially arbitrary. The natural choice is therefore a
standard 2-way implicitly authenticated key exchange, for which we choose [FHMQV](https://eprint.iacr.org/2009/408) ([doi](https://doi.org/10.1007/978-3-642-16441-5_6)). Compared
to just a static Diffie-Hellman exchange, this provides security against various secret leakages, including key compromise impersonation (KCI) attacks.

In addition, we wish the server to verify that some fingerprint information for the device remains the same between authentications, and we wish to do this in a privacy-conscious way,
without storing any readable fingerprint data persistently. To achieve this, instead of directly storing a long-term secret key for associating with the device, we instead store a
salt (identifying a member of a pseudorandom function family) and derive the secret key from that salt and the fingerprint information.

Specifically, the modified parts of the protocol are as follows. The device stores a long term device key `a` (with `A = a G`) and also the server's public key `B = H2(s, fingerprint) G`.
The server stores its salt `s`.
```
Client                                                   Server
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                         d <$- ℤ_|G_device|
                                                         D = d G
                                                         tf_spec = D
                                                         ... rest of server setup ...
                                               <----     k P*, Y*, tf_spec
dev_id <- look up stored device id
a <- look up stored device secret key
B <- look up stored server public key
c <$- ℤ_|G_device|
C = c G
tf_desc = (dev_id, C)
server_scale = H1(C, D, username, dev_id, instance_string)
device_scale = H1(D, C, username, dev_id, instance_string)
device_secret = c + device_scale a
tf_code = device_secret (D + server_scale B)
... rest of client authentication ...
X*, tf_desc, K_clientauth                      ---->
                                                         s <- look up stored salt for dev_id
                                                         fingerprint <- fingerprint the connecting device
                                                         A <- look up stored device public key for dev_id
                                                         b = H2(s, fingerprint)
                                                         server_scale = H1(C, D, username, dev_id, instance_string)
                                                         device_scale = H1(D, C, username, dev_id, instance_string)
                                                         server_secret = d + server_scale b
                                                         tf_code = server_secret (C + device_scale A)
                                                         ... rest of server authentication ...
```

### Single-use Recovery Codes

Similarly to remembered devices, recovery codes can use essentially arbitrary algorithms. However, since they may be written down by humans, the data storage is severely limited. We do
not need to restrict to nearly the tiny sizes other systems use for recovery codes (often 8 hexidecimal characters), but a limit of 30 characters seems quite usable: it does not take up
that much physical space, can reasonably (if not pleasantly) be transcribed by a human, and can be broken into 5 sections of 6 for easy readability and alignment, as in the following.
```
abcdef-abcdef-abcdef-abcdef-abcdef
```
With a base32 encoding (so that it can be case insensitive), this holds 150 bits of information, which we divide into
- 5 bits of index information, denoting which recovery code from a set is being entered. This allows issuing up to 32 codes per user at a time
  and only needing to check one signature.
- 15 bits of checksum, to catch human transcription errors. Imitating the strategy of [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) by using their character
  mapping informed by visual similarity data then searching for a code that catches a low number of bit errors seems like a good plan.
- 2 bits of version information, currently set to 0, in case the hashing of recovery codes changes.
- 128 bits of randomness, which holds the keying information actually used to authenticate.

Due to the limited space, we choose to give up on security upon compromise of the recovery code and (mostly, see TODO) two-way authentication. This means that an attacker who steals a
recovery code and has a user's password can impersonate the server to the user. However, especially as recovery codes are single use and not stored in a standardized location, this
does not seem to be a massive problem.

TODO: Determine if not sending the public key anywhere over the wire provides meaningful two-way authentication.

As such, we just derive a secret key from the recovery code, where the public key is stored server-side, and use an FXCR signature to indicate knowledge of the code. This is quite similar
to the Schnorr key case described above. As always when taking input from the user, we immediately hash it with the instance string to combat phishing (though it does not seem particularly
relevant in this case). Specifically, the changes to the protocol are as follows.

```
Client                                                   Server
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                         d <$- ℤ_|G_device|
                                                         D = d G
                                                         tf_spec = D
                                                         ... rest of server setup ...
                                               <----     k P*, Y*, tf_spec
r <$- ℤ_|G_device|
R = r G
index, recov_version, keying_info, checksum <- get recovery code from user
validate the checksum and notify the user if failed
tf_desc = (index, R)
q = H1(keying_info, instance_string)
e = H2(D, R)
s = r + q e
tf_code = s D
... rest of client authentication ...
X*, tf_desc, K_clientauth                      ---->
                                                         Q <- look up recovery public key for index
                                                         e = H2(D, R)
                                                         tf_code = d (R + q Q)
                                                         ... rest of server authentication ...
```

## Offline password stretching

To combat ever-increasing computing power, it is important to regularly increase the requirements for hashing a password. Since many users may reauthenticate with a password only rarely,
this should be possible with no user interaction. However, the user key cannot be easily changed without user interaction, since it would likely at least involve reencrypting application data.
To keep the same user key, we have the user key derived from the password and a random salt; the salt can then be iteratively encrypted with the result of more and more expensive hash functions,
making it possible to recover the original salt with logging from the hashing process.

TODO: Would it be simpler for the user key to be just random and have the initial "salt" be an encryption of that key under whatever is derived from the password?

Note that I believe XOR to be safe for encrypting the salt, but it is slightly harder to make a security argument given strong regularities in XOR that lead to things like Wagner's generalized
birthday attack. However, the server is assumed to be honest in this instance, as if a malicious server wished to not increase security, they could simply keep the old values around. Additionally,
since each extra hashing step depends on the previous steps, there is no way to exploit the regularity. TODO: formalize this

```
offset_salt, offset_augment, bpwd_shared' = PBKDF'(B_augment, bpwd_shared)
salt' = Encrypt(offset_salt, salt)
B_augment' = B_augment + offset_augment G
bpwd_augment' = bpwd_augment + offset_augment
```

## Instantiation Notes

- For simplicity, our instantiation hashes the entire protocol transcript in `H_session`, including the OPRF parts. This entirely removes message malleability.
  - This prevents a theoretical middlebox that attempts to unlink OPRF clients from which messages they are sending by reblinding `P*`. This seems
    hardly useful, however, as `username` must be sent in the clear.
- To reduce the amount of state necessary for the server to hold between requests, we order the parameters of `H_session` so that all values known before the second round come first

Properties:
  Strong augmented PAKE (following the OPAQUE paper, construction 1)
    No precomputation
    Even a MITM attacker can only get a single guess from a single connection (no dictionary attacks)
  Gives the client access to a password derived secret that the server does not know
  Client never learns whether the password or the two-factor code were incorrect
    In many cases, neither does the server (it needs a doable but not trivial brute force search to distinguish)
  Neither of the values returned by the protocol are sufficient to do a dictionary attack
  Robustness against discrete logarithm breaks
    Requires a discrete logarithm for every password attempt (assuming just have transcript)
      In contrast to OPAQUE-HMQV, which needs a single discrete logarithm that unlocks a simple dictionary attack
    Really, Diffie-Hellman, not DL
    Add bit security of CDH to bit security (entropy in dictionary) of password
  In case of quantmageddon (discrete logarithms are easy)
    With just K_client and K_session
      No dictionary attack
      Can (trivially) get K_client and K_session
      No replay/ability to log in later
    With just transcript
      Can do a dictionary attack on password and two-factor code, but must guess both simultaneously
        However, the two factor code is only behind a cheap hash and the password hashing work can be shared between attempts with the same password
        With short two factor codes (e.g. TOTP), this isn't much harder than a normal dictionary attack
      No access to K_client or K_session without a dictionary attack
      ?? No replay/ability to log in later
        I don't have a proof, but it looks right
    With transcript, K_client, and K_session
      ?? Identical to the just transcript case, but can obviously have K_client and K_session
    With MITM
      ?? Same as with passive transcript
        This really wants a proof

Tweaks:
  Instead of sending tf_desc in the clear, encrypt it using the rest of the parameters
    Very tricky to get right without breaking things
      If the (possibly false) server can confirm/deny the correctness of the decryption, they can do a dictionary attack on the password without the two-factor code
    Want to use a non-expanding stream cipher with no authentication
    tf_desc needs to be indistinguishable from random

Implementation notes:
- Values stored on disk: `k`, `bpwd_shared`, `B_augment = bpwd_augment G`, major version number, `tf_spec`, two factor secrets, `s`
- Everything about a user should be looked up atomically. This means that all the "lookups" in the second round are really done in the first round and saved as state for this login attempt.
- Ordering the arguments to `H_session` carefully can reduce the amount of state between communication rounds that the server needs to keep.
    1st round: Y*, username, version, E_augment, bpwd_shared, tf_spec
    2nd round: X*, E_shared, tf_desc, tf_code
    State necessary:
      State of the hash function H_session
      H2(bpwd_shared, "client")
      y
      s
      tf_spec (i.e. what two factor codes are acceptable)

Patent notes:
  Ug. Ug. Ug. Things seem to have expired, I think?
  Inner part (SPAKE2+EE) may be equivalent to an instantiation of PAK?
    https://datatracker.ietf.org/ipr/1283/
    According to Google, 5241599 is expired, but 7047408 is not
    Seems safe after 2023?

--------------------------------------------------------------------------------------
# "Frequently Asked" Questions

## What about "don't roll your own crypto"?
This is good advice that doesn't apply here for two reasons:
- No existing work provides the guarantees and features that this protocol does, so there isn't anything to reuse wholesale.
- This isn't anything fundamentally new, just composing existing, well-studied and already implemented pieces in ways have that are
  also fairly well understood.
It is of course possible that I made some major mistake here. I do plan to flesh out my proof sketches of security and would love to
see independent analysis. However, even if the protocol is completely broken, deploying it over TLS should result in no less security
than what people typically do, sending unhashed passwords directly to a server for verification.

## Why not use [OPAQUE](https://eprint.iacr.org/2018/163) ([doi](https://doi.org/10.1007/978-3-319-78372-7_15))?
The protocol presented here is a Strong aPAKE in the OPAQUE terminology as proven by them in section 4, their first contruction, a compiler
from aPAKE (in this instance, SPAKE2+) via OPRF. Their more lightweight construction based on AKE-KCI, which drives their OPAQUE instantiation,
saves some computation and a message of communication. However,
- The saved message of communication is only useful if the server wishes to initiate the encrypted communication without an encryped request from
  the client. While this situation can arise, it requires more careful integration with application code, which is often request/response-oriented.
- The saved computation is dwarfed by the cost of password hashing.
- In OPAQUE, the client learns of successful authentication before the server does. This makes in nigh impossible to integrate the protocol with
  arbitrarily complex other authentication factors.

## Why bother with the extra server-stored salt?
The extra salt at sent by the server upon login simplifies the security argument that exposure of the user key does not affect the security of
the protocol and the user's password. Additionally, it is essential for offline password stretching because it can encode the information to
reverse the more-hashed password back to the original user key.
