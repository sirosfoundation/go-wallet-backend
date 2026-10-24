# Real Android key-attestation chains

`TestAndroidKeyAttestation_RealPixelChains` verifies chains captured from real
devices. It is skipped while this directory holds no chains. Nothing here is
synthetic: do not commit generated chains.

## Files

* `roots.pem` - the pinned trust anchors for the test: Google's hardware
  attestation roots from https://android.googleapis.com/attestation/root
  (a JSON array of PEM strings; concatenate them).
* `<name>.pem` - one captured chain, PEM CERTIFICATE blocks, LEAF FIRST.
* `<name>.json` - what was captured:

      {
        "wia_challenge": "<the WIA challenge string C used for the capture>",
        "captured_at":   "2026-10-30T12:00:00Z",
        "app_digest":    "<hex SHA-256 of the app signing certificate>",
        "expect_home":   "tee" | "strongbox" | "none"
      }

  `captured_at` matters: chains are verified at that instant, because
  remote-provisioned leaf certificates are short lived.

## Capturing on a Pixel

Generate an EC P-256 key in the Android Keystore with the challenge derived from
a WIA challenge C (the string exactly as `POST /wallet-provider/wia/challenge`
returned it):

    val challenge = MessageDigest.getInstance("SHA-256")
        .digest(("siros-instance-key-v1" + c).toByteArray(Charsets.UTF_8))
    val spec = KeyGenParameterSpec.Builder("siros-instance-key",
            KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAttestationChallenge(challenge)
        .setIsStrongBoxBacked(true)   // false for a TEE capture
        .build()
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        .apply { initialize(spec) }.generateKeyPair()
    val chain = KeyStore.getInstance("AndroidKeyStore")
        .apply { load(null) }.getCertificateChain("siros-instance-key")

Write `chain[i].encoded` as PEM, leaf first. The app must be the signed wallet
build whose signing-certificate digest goes in `app_digest`. Capture one chain
with StrongBox and one without, plus (optionally) one from a device with an
unlocked bootloader; the boot state is recorded, not required.
