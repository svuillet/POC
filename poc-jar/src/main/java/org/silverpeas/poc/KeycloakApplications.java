package org.silverpeas.poc;

import jakarta.json.Json;
import jakarta.json.JsonArray;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class KeycloakApplications {

    private final HttpClient client = HttpClient.newHttpClient();

    // -----------------------------------------------------------------------
    // Authentification
    // -----------------------------------------------------------------------

    public String getAdminToken(
            String keycloakUrl,
            String realm,
            String clientId,
            String clientSecret)
            throws IOException, InterruptedException {

        String body =
                "grant_type=client_credentials"
                        + "&client_id=" + encode(clientId)
                        + "&client_secret=" + encode(clientSecret);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(
                        keycloakUrl
                                + "/realms/"
                                + realm
                                + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(
                    "Erreur authentification : "
                            + response.statusCode()
                            + "\n"
                            + response.body());
        }

        return parseJson(response.body()).getString("access_token");
    }

    // -----------------------------------------------------------------------
    // Utilisateurs
    // -----------------------------------------------------------------------

    public JsonObject getUser(
            String keycloakUrl,
            String realm,
            String username,
            String accessToken)
            throws IOException, InterruptedException {

        String endpoint =
                keycloakUrl
                        + "/admin/realms/"
                        + realm
                        + "/users?username="
                        + encode(username)
                        + "&exact=true";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(response.body());
        }

        JsonArray users = parseJsonArray(response.body());

        if (users.isEmpty()) {
            return null;
        }

        return users.getJsonObject(0);
    }

    // -----------------------------------------------------------------------
    // Groupes utilisateur
    // -----------------------------------------------------------------------

    public JsonArray getUserGroups(
            String keycloakUrl,
            String realm,
            String userId,
            String accessToken)
            throws IOException, InterruptedException {

        String endpoint =
                keycloakUrl
                        + "/admin/realms/"
                        + realm
                        + "/users/"
                        + userId
                        + "/groups";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(response.body());
        }

        return parseJsonArray(response.body());
    }

    // -----------------------------------------------------------------------
    // Applications (clients Keycloak)
    // -----------------------------------------------------------------------

    public JsonArray getClients(
            String keycloakUrl,
            String realm,
            String accessToken)
            throws IOException, InterruptedException {

        String endpoint =
                keycloakUrl
                        + "/admin/realms/"
                        + realm
                        + "/clients";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(response.body());
        }

        return parseJsonArray(response.body());
    }

    // -----------------------------------------------------------------------
    // Applications accessibles
    // -----------------------------------------------------------------------

    public List<String> getAccessibleApplications(
            String keycloakUrl,
            String realm,
            String username,
            String accessToken)
            throws IOException, InterruptedException {

        JsonObject user =
                getUser(keycloakUrl, realm, username, accessToken);

        if (user == null) {
            return List.of();
        }

        String userId = user.getString("id");

        JsonArray groups =
                getUserGroups(keycloakUrl, realm, userId, accessToken);

        List<String> applications = new ArrayList<>();

        for (int i = 0; i < groups.size(); i++) {

            JsonObject group = groups.getJsonObject(i);
            String path = group.getString("path");

            if (path.startsWith("/Applications/")) {

                applications.add(
                        path.substring("/Applications/".length()));
            }
        }

        return applications;
    }

    // -----------------------------------------------------------------------
    // Affichage
    // -----------------------------------------------------------------------

    public void printApplications(
            JsonArray clients,
            List<String> userApplications) {

        Set<String> accessibles = new HashSet<>(userApplications);

        System.out.printf("%-30s %-10s%n",
                "Application", "Accès");
        System.out.println("-----------------------------------------------");

        for (int i = 0; i < clients.size(); i++) {

            JsonObject client = clients.getJsonObject(i);

            String clientId = client.getString("clientId");

            if ("account".equals(clientId)
                    || "realm-management".equals(clientId)
                    || "admin-cli".equals(clientId)
                    || "broker".equals(clientId)) {
                continue;
            }

            boolean ok = accessibles.contains(clientId);

            System.out.printf("%-30s %s%n",
                    clientId,
                    ok ? "OUI" : "NON");
        }
    }

    // -----------------------------------------------------------------------
    // JSON
    // -----------------------------------------------------------------------

    private JsonObject parseJson(String json) {

        try (JsonReader reader =
                     Json.createReader(new StringReader(json))) {

            return reader.readObject();
        }
    }

    private JsonArray parseJsonArray(String json) {

        try (JsonReader reader =
                     Json.createReader(new StringReader(json))) {

            return reader.readArray();
        }
    }

    private static String encode(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // -----------------------------------------------------------------------
    // Test
    // -----------------------------------------------------------------------

    public static void main(String[] args) {

        String keycloakUrl = "http://localhost:8080";
        String realm = "silverpeas-realm";

        String clientId = "silverpeas-admin";
        String clientSecret = "dUqkexpRavebI6Z0tFRpngNeJIpfiPhI";

        String username = "svuillet";

        KeycloakApplications keycloak = new KeycloakApplications();

        try {

            System.out.println("=== Connexion à Keycloak ===");

            String token =
                    keycloak.getAdminToken(
                            keycloakUrl,
                            realm,
                            clientId,
                            clientSecret);

            System.out.println("Authentification OK");

            JsonArray clients =
                    keycloak.getClients(
                            keycloakUrl,
                            realm,
                            token);

            List<String> applications =
                    keycloak.getAccessibleApplications(
                            keycloakUrl,
                            realm,
                            username,
                            token);

            System.out.println();
            System.out.println("Utilisateur : " + username);

            System.out.println("Applications accessibles :");
            applications.forEach(app -> System.out.println(" - " + app));

            System.out.println();
            keycloak.printApplications(clients, applications);

        } catch (Exception e) {

            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }
}