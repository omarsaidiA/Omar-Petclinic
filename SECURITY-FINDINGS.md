# Security findings — omar-petclinic

Registre des vulnérabilités trouvées sur le projet d'origine
([spring-petclinic-rest](https://github.com/spring-petclinic/spring-petclinic-rest)) puis corrigées.
Chaque entrée indique l'outil ou la méthode de détection, la sévérité, la correction et l'état
avant/après mesuré.

Les scans ont été lancés en local avec les mêmes images et versions que le pipeline
[`devsecops.yml`](.github/workflows/devsecops.yml) : Gitleaks 8.30.1, Semgrep 1.182.1, Trivy 0.76.1
et ZAP 2.17.0. Le DAST a été lancé avec un token VET contre la stack `docker compose`.

## Synthèse par outil

| Outil | Périmètre | Avant | Après |
|---|---|---|---|
| Gitleaks | 788 commits (historique complet) | 0 secret | 0 secret |
| Semgrep (`p/java`, `p/owasp-top-ten`) | Code Java, workflows, config | 11 constats (niveau warning) | 0 |
| Trivy (SCA, jar et `pom.xml`) | Dépendances livrées | 1 Medium | 0 |
| Trivy (image) | Alpine 3.24 et jar | 0 HIGH/CRITICAL corrigeable | 0 |
| ZAP baseline (authentifié) | 44 endpoints OpenAPI et 110 URLs explorées | **1 High**, 1 Medium, 1 Info | 0 High, 1 Medium accepté, 1 faux positif filtré |
| Revue manuelle et tests d'intégration | Contrôles d'accès, données sensibles, configuration | 13 constats | 0 |

## Détail des vulnérabilités

Sévérités : celle de l'outil quand il en donne une. Pour la revue manuelle, c'est une estimation
fondée sur l'impact et l'exploitabilité, dans l'esprit du CVSS.

### Contrôle d'accès

| ID | Détection | Vulnérabilité | Sévérité | Correction | Avant → Après |
|---|---|---|---|---|---|
| F-01 | Revue manuelle | API entièrement ouverte : `petclinic.security.enable=false` par défaut, `GET /api/owners` répond sans authentification (CWE-306) | Critique | Resource server OAuth2 : JWT Keycloak obligatoire (signature, `iss`, `aud`), API stateless (Phase 3) | 200 sans token → **401** |
| F-02 | Revue manuelle, puis test | **BOLA/IDOR** : `PUT /api/owners/{ownerId}/pets/{petId}` modifie l'animal d'un autre propriétaire, l'appartenance n'est pas vérifiée (OWASP API1:2023, CWE-639). Le test d'origine `testUpdateOwnersPetSuccess` validait ce comportement | Haute | L'animal est cherché via son propriétaire (`owner.getPet(petId)`) ; test de régression `cannotUpdateAPetThroughAnotherOwnersUrl` | `PUT /owners/1/pets/7` : 204 → **404** |
| F-03 | Revue manuelle, puis test | **BOLA/IDOR** : `POST /api/owners/{ownerId}/pets/{petId}/visits` ignore `ownerId` et attache la visite à n'importe quel animal (CWE-639) | Haute | Le propriétaire et l'appartenance de l'animal sont vérifiés, sinon 404 ; test `cannotAddAVisitToAPetThroughAnotherOwnersUrl` | `POST /owners/1/pets/7/visits` : 201 → **404** |
| F-04 | Revue manuelle | Aucune séparation des données entre propriétaires : rôles `OWNER_ADMIN`/`VET_ADMIN` grossiers, pas de notion de « ses propres données » (CWE-285) | Haute | RBAC ADMIN/VET/OWNER par `@PreAuthorize` ; `OwnershipEvaluator` compare le claim `owner_id` du token à la ressource demandée | Tout utilisateur authentifié lit tout → un OWNER qui lit le propriétaire 2 reçoit **403** |
| F-05 | Test d'intégration | Divulgation des règles de validation à un non-admin : `@Valid` s'exécute avant `@PreAuthorize`, un VET qui envoie `{}` à `/api/users` reçoit un 400 détaillé (CWE-209) | Basse | Règle `hasRole("ADMIN")` au niveau URL sur `/api/users/**`, évaluée avant la lecture du corps | 400 détaillé → **403** |

### Données sensibles et cryptographie

| ID | Détection | Vulnérabilité | Sévérité | Correction | Avant → Après |
|---|---|---|---|---|---|
| F-06 | Revue manuelle | Mots de passe stockés **en clair** par `POST /api/users` (`UserServiceImpl.saveUser`) (CWE-256) | Haute | Hachage BCrypt coût 12 (format brut de 60 caractères pour la colonne `VARCHAR(60)`) ; longueur 12 à 72 (limite BCrypt) | Texte clair → `$2a$12$…` (test `shouldStoreOnlyABcryptHashOfThePassword`) |
| F-07 | Test d'intégration | La réponse de `POST /api/users` renvoie le mot de passe, en clair à l'origine, puis haché ; le générateur OpenAPI ignore `writeOnly` (CWE-200) | Moyenne | Champ `password` vidé avant la réponse ; test `createdUserPasswordIsNeverReturned` | Présent → **absent** |
| F-08 | Revue manuelle | Mot de passe de base de données par défaut en dur (`${POSTGRES_PASS:petclinic}`) et compose MySQL avec mot de passe root vide (CWE-798) | Moyenne | Aucune valeur par défaut, secrets via `.env` uniquement (`.env.example` fourni, `.env` ignoré par git) ; compose réécrit (Phase 2) | En dur → **variable d'environnement obligatoire** |

### Configuration et surface d'attaque

| ID | Détection | Vulnérabilité | Sévérité | Correction | Avant → Après |
|---|---|---|---|---|---|
| F-09 | Revue manuelle | Console H2 activée dans le profil par défaut : exécution SQL arbitraire, historique de RCE (CVE-2021-42392, CVE-2022-23221) | Haute | `spring.h2.console.enabled=false` | `/h2-console` exposé → **désactivé** |
| F-10 | Revue manuelle | CORS ouvert à **toutes les origines** : `@CrossOrigin` sans liste sur les 10 contrôleurs (CWE-942) | Moyenne | Annotations supprimées ; `CorsConfigurationSource` central, origines configurables, vide par défaut | Toute origine → **liste blanche** (test `corsAllowsOnlyConfiguredOrigins`) |
| F-11 | Revue manuelle | Fuite d'informations techniques : le `title` des erreurs contient le nom de la classe d'exception Java (`IllegalStateException`…) ; les tests d'origine l'exigeaient (CWE-209) | Basse | Libellé HTTP standard (`Bad Request`…) ; aucune stack trace (`server.error.*`) | Nom de classe → **libellé HTTP** |
| F-12 | Revue manuelle | Mauvais codes HTTP : un refus `@PreAuthorize` et du JSON invalide tombaient dans le handler générique et renvoyaient 500 | Basse | Handlers dédiés : 401, 403, 400, 405, 415, 404 | 500 → **403/400** |
| F-13 | ZAP | Document OpenAPI invalide : `info.license.extensions` généré par `SwaggerConfig`, ce qui bloquait l'import OpenAPI du DAST | Info | Ligne `setExtensions(emptyMap())` supprimée | Import en erreur → **44 endpoints importés** |

### Dépendances et chaîne d'approvisionnement

| ID | Détection | Vulnérabilité | Sévérité | Correction | Avant → Après |
|---|---|---|---|---|---|
| F-14 | **ZAP** (DAST) | Swagger UI embarque **DOMPurify 3.4.16** (CVE-2026-116802, CVE-2026-116803, CVE-2026-116804) | **Haute** | Webjar `swagger-ui` forcé en 5.34.1 (DOMPurify 3.4.17) **et** `springdoc.swagger-ui.version` aligné par filtrage Maven ; test `swaggerUiIsServedWithItsOwnCsp` | ZAP exit 1 → **alerte absente**, DOMPurify 3.4.17 servi |
| F-15 | Trivy (SCA) | `spring-retry` 1.0.3 (2014) tiré par `spring-data-jdbc-core`, CVE-2026-41710 (déni de service) | Moyenne | Dépendance transitive **exclue** : elle n'est pas utilisée | 1 → **0** |
| F-16 | Semgrep | 10 actions GitHub épinglées par tag mutable (`@v3`, `@v4`) : un tag déplacé exécute du code arbitraire dans le CI (CWE-1357, OWASP A08) | Moyenne | Workflows remplacés ; chaque action est épinglée par SHA de commit | 10 → **0** |
| F-17 | Semgrep | Dependabot sans période de *cooldown* (OWASP A08) | Basse | `cooldown` de 7 jours (14 jours pour les versions majeures) | 1 → **0** |
| F-18 | Revue manuelle | Auto-merge Dependabot sans revue, et workflow poussant l'image vers le Docker Hub du projet d'origine | Moyenne | Workflows supprimés ; chaque mise à jour passe par le pipeline et une revue | Supprimés |

## Risques acceptés et faux positifs

| ID | Outil | Constat | Décision |
|---|---|---|---|
| A-01 | ZAP (10055) | CSP `style-src 'unsafe-inline'` sur les pages Swagger UI | **Risque accepté**. Swagger UI injecte des styles inline et ne s'affiche pas sans. La politique reste stricte ailleurs : `script-src` sans inline, `frame-ancestors 'none'`, et les réponses de l'API ont `default-src 'none'`. En production, `SWAGGER_UI_ENABLED=false` supprime cette surface. |
| A-02 | ZAP (10096) | *Timestamp Disclosure* dans `swagger-ui-standalone-preset.js` | **Faux positif**. Les valeurs (`1732584193` = `0x67452301`…) sont des constantes d'initialisation MD5/SHA-1. Le filtre du plan ZAP se limite aux deux fichiers de Swagger UI, donc une vraie fuite ailleurs resterait signalée. |

## Risques résiduels connus

- **Keycloak en `start-dev`** (HTTP, base embarquée) et **password grant** activé pour les tests
  `curl` : réservés au développement. Une production utiliserait `start` avec TLS, une base
  externe et le flux *authorization code* avec PKCE.
- **HSTS** n'est émis que sur HTTPS. Un reverse proxy TLS est nécessaire devant l'API, avec
  `server.forward-headers-strategy` configuré.
- **Rate limiting en mémoire** : il est propre à chaque instance. Une montée en charge
  horizontale demanderait un stockage partagé (Bucket4j avec Redis, par exemple). Les requêtes avec
  un token invalide sont rejetées avant le filtre et ne sont pas comptées ; la validation JWT reste
  peu coûteuse.
- **Table `users` héritée** : elle ne sert plus à l'authentification, Keycloak est la seule source
  d'identité. Elle contient encore un compte `admin` d'exemple, haché en BCrypt.

## Leçons tirées

1. **Un scan vide n'est pas une preuve.** Après la mise à jour du webjar, ZAP ne signalait plus
   rien… parce que Swagger UI renvoyait 404 : springdoc fixe en dur la version de webjar attendue.
   Un scan témoin contre l'ancienne version a révélé le problème. Il est maintenant couvert par un
   test.
2. **Les outils se complètent.** Trivy (SCA) ne voit pas une bibliothèque JavaScript enfouie dans
   un webjar ; ZAP (DAST) la détecte dans la réponse HTTP. À l'inverse, Trivy trouve une CVE Java
   qu'aucun scan dynamique ne pouvait voir.
3. **Les failles d'autorisation (BOLA) échappent aux scanners.** F-02 et F-03 ont été trouvées en
   lisant le code ; un test d'origine validait même la faille. Seuls des tests d'intégration rôle
   par rôle les empêchent de revenir.
4. **Le DAST doit être authentifié.** Sans token, ZAP ne voit que des 401. Le token est injecté
   par `-config replacer…`, car le *replacer* du plan n'interprète pas les variables
   d'environnement (vérifié avec un serveur d'écho).
