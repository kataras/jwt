package jwt

import (
	"crypto"
	"encoding/json"
	"fmt"
)

// Enrich verifies a token, merges extra claims into its payload and signs the result.
//
// A JWT payload cannot be edited in place, because the signature covers the header and
// the payload together. Enrich therefore produces a new token rather than modifying the
// one you pass in.
//
// The algorithm is a parameter, not something read out of the token. That is the whole
// point of the signature it performs first: given only the token, a caller could be handed
// a header naming the unsecured algorithm and would then sign an attacker's claims with
// its own private key. Enrich now refuses that, and refuses NONE outright.
//
// The verification key is derived from key. HMAC uses the same key both ways, and every
// asymmetric private key this package accepts exposes its own public half.
//
// The header of the verified token is carried through unchanged, so a "kid" survives
// enrichment. Only the algorithm is pinned, so a "kid" naming some other key is carried
// through as well; the token still verified under the key you gave, and a mismatch surfaces
// when the enriched token is verified through a Keys registry. Use Keys.EnrichToken when
// the registry should choose.
//
// Claims are merged the way Sign merges them, with the extra claims last. Merge splices
// JSON rather than reparsing it, so a claim restated in extraClaims appears twice in the
// payload. Go reads the last one; some other languages read the first. Encrypted tokens
// are not supported.
//
// Enrich checks the signature and the algorithm. It does not check expiry or any other
// claim, because the enriched token keeps the original "exp" and whoever verifies it next
// will. If you have already verified the token and want to skip the second check, use
// Decode followed by UnverifiedToken.Enrich, which costs about eight fewer allocations
// and leaves the safety argument with you.
//
// Example:
//
//	extraClaims := map[string]any{
//	    "role":        "admin",
//	    "permissions": []string{"read", "write"},
//	}
//
//	enrichedToken, err := jwt.Enrich(jwt.HS256, signingKey, existingToken, extraClaims)
//	if err != nil {
//	    return err
//	}
//
// It returns ErrTokenAlg when alg is nil, when alg is NONE, or when the token's header
// names a different algorithm. It returns ErrTokenSignature when the token was not signed
// with key, ErrInvalidKey when no public key can be derived from key, and a wrapped
// merge error when the extra claims cannot be serialized.
func Enrich(alg Alg, key PrivateKey, accessToken []byte, extraClaims any) ([]byte, error) {
	if alg == nil {
		return nil, ErrTokenAlg
	}

	if alg == NONE {
		return nil, fmt.Errorf("%w: refusing to enrich under the unsecured algorithm", ErrTokenAlg)
	}

	publicKey, err := publicKeyOf(key)
	if err != nil {
		return nil, err
	}

	// Check the signature before re-signing. The header validator pins the algorithm to
	// the one the caller named while tolerating extra header fields, because the default
	// header comparison is byte exact and would reject any token carrying a "kid".
	//
	// This goes through decodeToken rather than Verify on purpose. What Enrich needs is
	// the signature check and the algorithm pin, and nothing else: Verify would also
	// unmarshal the standard claims and run the validator chain, which costs about
	// nineteen allocations per call and answers a question Enrich does not ask. Claim
	// validation stays where it was, with whoever verifies the enriched token next.
	header, payload, signature, err := decodeToken(alg, publicKey, accessToken, pinnedAlgHeader(alg))
	if err != nil {
		return nil, err
	}

	unverified := &UnverifiedToken{
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}

	return unverified.enrich(alg, key, extraClaims, Base64Encode(header))
}

// pinnedAlgHeader returns a HeaderValidator that accepts any header naming the given
// algorithm, and no other.
//
// The algorithm is never taken from the token. It is compared against the one already
// chosen by the caller, which is what keeps a header that says "NONE" from selecting the
// unsecured algorithm.
func pinnedAlgHeader(expected Alg) HeaderValidator {
	name := expected.Name()

	return func(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error) {
		// json.Unmarshal rather than the package-level Unmarshal: this reads one string
		// field out of a header of a few dozen bytes, and the decoder-with-UseNumber
		// path that Unmarshal points at costs several allocations to answer that.
		var header headerWithAlg
		if err := json.Unmarshal(headerDecoded, &header); err != nil {
			return nil, nil, nil, err
		}

		if header.Alg != name {
			return nil, nil, nil, fmt.Errorf("%w: %s", ErrTokenAlg, header.Alg)
		}

		return expected, nil, nil, nil
	}
}

// publicKeyOf derives the verification key that matches a signing key.
//
// HMAC uses one key for both directions. Every asymmetric private key this package
// accepts implements crypto.Signer, which exposes its own public half, so no separate
// argument is needed.
func publicKeyOf(key PrivateKey) (PublicKey, error) {
	switch k := key.(type) {
	case []byte:
		return k, nil
	case crypto.Signer:
		return k.Public(), nil
	default:
		// A string is deliberately not accepted, even though it would produce a working
		// verification key. No algorithm in this package can sign with one, so accepting
		// it here only moved the rejection from before the signature check to after it,
		// where the error reads as a signing failure rather than a bad key.
		return nil, ErrInvalidKey
	}
}
