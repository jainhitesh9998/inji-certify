package io.mosip.certify.keyprovider.jca;

import io.mosip.certify.signing.SignatureAlgorithm;

/**
 * The ISO/IEC 18013-5:2021 Annex B Issuing Authority CA a dev-mode provider generates for local runs (decisions D2
 * and D3 of {@code docs/design/20-mdl-issuer.md}).
 *
 * <p>Only the fields an operator chooses are here; the profile itself (key usage, basic constraints, key identifier,
 * validity caps) comes from {@code certify-pki} {@code IsoMdocProfiles}, so a generated IACA is the certificate the
 * Annex B validator accepts. Every field is required except {@code state}, one of {@code issuerAltUri} and
 * {@code issuerAltEmail}, and {@code validityYears} (which defaults to the 20-year Annex B maximum).
 *
 * @param algorithm      the IACA signing key algorithm; {@code certify-pki} allows P-256/384/521 (ES256/384/512)
 * @param country        subject country (C), ISO 3166-1 alpha-2
 * @param state          subject state (ST), optional
 * @param commonName     subject common name (CN); a demo or test CA should say so
 * @param issuerAltUri   issuerAltName URI, mutually exclusive with {@code issuerAltEmail}
 * @param issuerAltEmail issuerAltName mailbox, mutually exclusive with {@code issuerAltUri}
 * @param crlUri         CRL distribution point, an absolute http(s) URI
 * @param validityYears  requested lifetime in years, {@code null} for the 20-year maximum
 */
public record MdocIacaSpec(SignatureAlgorithm algorithm, String country, String state, String commonName,
                           String issuerAltUri, String issuerAltEmail, String crlUri, Integer validityYears) {
}
