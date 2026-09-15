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
import java.util.List;

public class KeycloakGroups {

    private final HttpClient client = HttpClient.newHttpClient();

    /**
     * Récupère un token d'administration avec le Service Account
     * du client Keycloak.
     */
    public String getAdminToken(
            String keycloakUrl,
            String realm,
            String clientId,
            String clientSecret)
            throws IOException, InterruptedException {

        String body =
                "grant_type=client_credentials" +
                        "&client_id=" + encode(clientId) +
                        "&client_secret=" + encode(clientSecret);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(
                        keycloakUrl
                                + "/realms/"
                                + realm
                                + "/protocol/openid-connect/token"))
                .header(
                        "Content-Type",
                        "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response =
                client.send(
                        request,
                        HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {

            throw new IOException(
                    "Erreur authentification Keycloak : "
                            + response.statusCode()
                            + "\n"
                            + response.body());
        }

        JsonObject json = parseJson(response.body());

        return json.getString("access_token");
    }

    /**
     * Récupère tous les groupes du realm.
     *
     * L'API Keycloak renvoie les groupes racine avec leurs
     * sous-groupes dans la propriété "subGroups".
     */
    public JsonArray getGroups(
            String keycloakUrl,
            String realm,
            String accessToken)
            throws IOException, InterruptedException {

        String url =
                keycloakUrl
                        + "/admin/realms/"
                        + URLEncoder.encode(
                        realm,
                        StandardCharsets.UTF_8)
                        + "/groups";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header(
                        "Authorization",
                        "Bearer " + accessToken)
                .header(
                        "Accept",
                        "application/json")
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(
                        request,
                        HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {

            throw new IOException(
                    "Erreur récupération groupes Keycloak : "
                            + response.statusCode()
                            + "\n"
                            + response.body());
        }

        try (JsonReader reader =
                     Json.createReader(
                             new StringReader(response.body()))) {

            return reader.readArray();
        }
    }

    /**
     * Transforme l'arbre de groupes Keycloak en une liste plate.
     *
     * Exemple :
     *
     * /Applications
     *   /Applications/Silverpeas
     *   /Applications/GLPI
     *
     * devient :
     *
     * /Applications
     * /Applications/Silverpeas
     * /Applications/GLPI
     */
    public List<String> getAllGroupPaths(JsonArray groups) {

        List<String> result = new ArrayList<>();

        for (int i = 0; i < groups.size(); i++) {

            JsonObject group = groups.getJsonObject(i);

            extractGroupPaths(
                    group,
                    result);
        }

        return result;
    }

    /**
     * Parcours récursivement un groupe et ses sous-groupes.
     */
    private void extractGroupPaths(
            JsonObject group,
            List<String> result) {

        String path = group.getString(
                "path",
                null);

        if (path != null) {
            result.add(path);
        }

        JsonArray subGroups =
                group.getJsonArray(
                        "subGroups"
                );

        for (int i = 0; i < subGroups.size(); i++) {

            JsonObject subGroup =
                    subGroups.getJsonObject(i);

            extractGroupPaths(
                    subGroup,
                    result);
        }
    }

    /**
     * Affiche l'arborescence complète des groupes.
     */
    public void printGroups(JsonArray groups) {

        System.out.println("=== Groupes Keycloak ===");

        for (int i = 0; i < groups.size(); i++) {

            JsonObject group =
                    groups.getJsonObject(i);

            printGroup(
                    group,
                    0);
        }
    }

    /**
     * Affiche récursivement un groupe.
     */
    private void printGroup(
            JsonObject group,
            int level) {

        String name =
                group.getString(
                        "name",
                        "");

        String path =
                group.getString(
                        "path",
                        "");

        System.out.println(
                "  ".repeat(level)
                        + "- "
                        + name
                        + " ["
                        + path
                        + "]");

        JsonArray subGroups =
                group.getJsonArray(
                        "subGroups"
                );

        for (int i = 0; i < subGroups.size(); i++) {

            printGroup(
                    subGroups.getJsonObject(i),
                    level + 1);
        }
    }

    /**
     * Récupère un groupe par son chemin.
     */
    public JsonObject findGroup(
            JsonArray groups,
            String groupPath) {

        for (int i = 0; i < groups.size(); i++) {

            JsonObject group =
                    groups.getJsonObject(i);

            JsonObject result =
                    findGroupRecursive(
                            group,
                            groupPath);

            if (result != null) {
                return result;
            }
        }

        return null;
    }

    /**
     * Recherche récursive d'un groupe.
     */
    private JsonObject findGroupRecursive(
            JsonObject group,
            String groupPath) {

        String path =
                group.getString(
                        "path",
                        null);

        if (groupPath.equals(path)) {
            return group;
        }

        JsonArray subGroups =
                group.getJsonArray(
                        "subGroups"
                );

        for (int i = 0; i < subGroups.size(); i++) {

            JsonObject result =
                    findGroupRecursive(
                            subGroups.getJsonObject(i),
                            groupPath);

            if (result != null) {
                return result;
            }
        }

        return null;
    }

    /**
     * Parse un objet JSON.
     */
    private JsonObject parseJson(String json) {

        try (JsonReader reader =
                     Json.createReader(
                             new StringReader(json))) {

            return reader.readObject();
        }
    }

    /**
     * Encode une valeur pour application/x-www-form-urlencoded.
     */
    private static String encode(String value) {

        return URLEncoder.encode(
                value,
                StandardCharsets.UTF_8);
    }

    /**
     * Exemple d'utilisation.
     */
    public static void main(String[] args) {

        String keycloakUrl =
                "http://localhost:8080";

        String realm =
                "silverpeas-realm";

        /*
         * Client Keycloak disposant d'un Service Account.
         */
        String clientId =
                "silverpeas-admin";

        String clientSecret = "dUqkexpRavebI6Z0tFRpngNeJIpfiPhI";


        if (clientSecret == null
                || clientSecret.isBlank()) {

            System.err.println(
                    "La variable KEYCLOAK_CLIENT_SECRET "
                            + "n'est pas définie.");

            return;
        }

        KeycloakGroups keycloak =
                new KeycloakGroups();

        try {

            System.out.println(
                    "=== Connexion à Keycloak ===");

            String accessToken =
                    keycloak.getAdminToken(
                            keycloakUrl,
                            realm,
                            clientId,
                            clientSecret);

            System.out.println(
                    "✅ Authentification réussie");

            System.out.println(
                    "\n=== Récupération des groupes ===");

            JsonArray groups =
                    keycloak.getGroups(
                            keycloakUrl,
                            realm,
                            accessToken);

            keycloak.printGroups(groups);

            System.out.println(
                    "\n=== Liste plate des groupes ===");

            List<String> groupPaths =
                    keycloak.getAllGroupPaths(
                            groups);

            for (String path : groupPaths) {
                System.out.println(
                        " - " + path);
            }

            System.out.println(
                    "\nNombre de groupes : "
                            + groupPaths.size());

            /*
             * Exemple de recherche.
             */
            String searchedGroup =
                    "/Applications/SILVERPEAS";

            JsonObject group =
                    keycloak.findGroup(
                            groups,
                            searchedGroup);

            if (group != null) {

                System.out.println(
                        "\nGroupe trouvé : "
                                + group.getString(
                                "name"));

                System.out.println(
                        "ID : "
                                + group.getString(
                                "id"));

                System.out.println(
                        "Path : "
                                + group.getString(
                                "path"));
            }

        } catch (Exception e) {

            System.err.println(
                    "❌ Erreur : "
                            + e.getMessage());

            e.printStackTrace();
        }
    }
}