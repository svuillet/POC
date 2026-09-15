package org.silverpeas.poc;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class KeycloakUserInfo {

    private final HttpClient client = HttpClient.newHttpClient();

    /**
     * Authentifie un utilisateur et retourne son access token.
     */
    public String login(String url, String realm, String clientId,
                        String username, String password)
            throws IOException, InterruptedException {

        String body =
                "grant_type=password" +
                        "&client_id=" + encode(clientId) +
                        "&username=" + encode(username) +
                        "&password=" + encode(password) +
                        "&scope=openid";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url + "/realms/" + realm + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            System.err.println("Erreur Keycloak : " + response.statusCode());
            System.err.println(response.body());
            return null;
        }

        JsonObject json = parseJson(response.body());
        return json.getString("access_token");
    }

    /**
     * Appelle l'endpoint /userinfo.
     */
    public JsonObject userInfo(String url, String realm, String accessToken)
            throws IOException, InterruptedException {

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url + "/realms/" + realm + "/protocol/openid-connect/userinfo"))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("Erreur userinfo : " + response.body());
        }

        return parseJson(response.body());
    }

    /**
     * Retourne la valeur d'un attribut (standard ou personnalisé).
     */
    public String getAttribute(JsonObject user, String attributeName) {
        return user.getString(attributeName, null);
    }

    /**
     * Affiche tous les champs retournés par /userinfo.
     */
    public void printAttributes(JsonObject user) {
        user.forEach((key, value) ->
                System.out.println(key + " = " + value));
    }

    /**
     * Parse une chaîne JSON en JsonObject.
     */
    private JsonObject parseJson(String json) {
        try (JsonReader reader = Json.createReader(new StringReader(json))) {
            return reader.readObject();
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // ----------------------------------------------------------------------
    // Test
    // ----------------------------------------------------------------------

    public static void main(String[] args) {

        // Configuration de ton Keycloak Docker
        String keycloakUrl = "http://localhost:8080";
        String realm = "silverpeas-realm";
        String clientId = "silverpeas";

        // Utilisateur de test
        String username = "svuillet";
        String password = "silver2006";

        KeycloakUserInfo keycloak = new KeycloakUserInfo();

        try {
            System.out.println("=== Test authentification Keycloak ===");

            String accessToken = keycloak.login(
                    keycloakUrl,
                    realm,
                    clientId,
                    username,
                    password
            );

            if (accessToken == null) {
                System.err.println("❌ Authentification échouée.");
                return;
            }

            System.out.println("✅ Authentification réussie");
            System.out.println("Access token : "
                    + accessToken.substring(0, Math.min(40, accessToken.length()))
                    + "...");

            System.out.println("\n=== /userinfo ===");

            JsonObject user = keycloak.userInfo(
                    keycloakUrl,
                    realm,
                    accessToken
            );

            // Affiche le JSON complet
            keycloak.printAttributes(user);

            System.out.println("\n=== Attributs principaux ===");
            System.out.println("Id        : " + keycloak.getAttribute(user, "sub"));
            System.out.println("Username  : " + keycloak.getAttribute(user, "preferred_username"));
            System.out.println("Prénom    : " + keycloak.getAttribute(user, "given_name"));
            System.out.println("Nom       : " + keycloak.getAttribute(user, "family_name"));
            System.out.println("Email     : " + keycloak.getAttribute(user, "email"));

            System.out.println("\n=== Attributs personnalisés ===");
            System.out.println("Phone     : " + keycloak.getAttribute(user, "phone"));
            System.out.println("Service   : " + keycloak.getAttribute(user, "service"));
            System.out.println("Site      : " + keycloak.getAttribute(user, "site"));

        } catch (Exception e) {
            System.err.println("Erreur lors du test : " + e.getMessage());
            e.printStackTrace();
        }
    }
}