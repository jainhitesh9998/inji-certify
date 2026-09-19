package io.mosip.certify.proof;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Fetches a DID document by URL; the HTTPS implementation is the production one, tests substitute a stub. */
@FunctionalInterface
public interface DidDocumentFetcher {

    String fetch(URI url) throws IOException;

    /** did:web documents are served over HTTPS only (W3C did:web method, section 3.2). */
    static DidDocumentFetcher https(Duration timeout) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
        return url -> {
            if (!"https".equals(url.getScheme())) {
                throw new IOException("did:web documents are fetched over https only: " + url);
            }
            try {
                HttpResponse<String> response = client.send(HttpRequest.newBuilder(url).timeout(timeout).header("Accept", "application/did+json, application/json").GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new IOException("DID document " + url + " answered " + response.statusCode());
                }
                return response.body();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while fetching " + url, e);
            }
        };
    }
}
