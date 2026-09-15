package org.silverpeas.poc;


import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class KeycloakAuthenticator {

    private final HttpClient client = HttpClient.newHttpClient();

    private final String keycloakUrl;
    private final String realm;
    private final String clientId;

    public KeycloakAuthenticator(String keycloakUrl, String realm, String clientId) {
        this.keycloakUrl = keycloakUrl;
        this.realm = realm;
        this.clientId = clientId;
    }

    /**
     * Vérifie un login/mot de passe auprès de Keycloak.
     *
     * @return true si l'authentification est valide.
     */
    public boolean authenticate(String username, String password)
            throws IOException, InterruptedException {

        String body =
                "grant_type=password" +
                        "&client_id=" + encode(clientId) +
                        "&username=" + encode(username) +
                        "&password=" + encode(password) +
                        "&scope=openid";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(keycloakUrl +
                        "/realms/" + realm +
                        "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            System.out.println("Authentification OK");
            return true;
        }

        System.out.println("Erreur Keycloak : " + response.statusCode());
        System.out.println(response.body());
        return false;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {

        KeycloakAuthenticator auth = new KeycloakAuthenticator(
                "http://localhost:8080",
                "silverpeas-realm",
                "silverpeas"
        );

        boolean ok = auth.authenticate("svuillet", "silver2006");

        System.out.println("Résultat = " + ok);
    }
}