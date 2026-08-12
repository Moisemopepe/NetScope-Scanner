# Modèle de sécurité NetScope Scanner

NetScope Scanner est conçu pour l'analyse défensive de réseaux autorisés.

## Principes

- Aucun exploit, brute force ou contournement d'authentification.
- Connexions TCP courtes pour identifier les ports ouverts.
- Détection de version non intrusive par bannière, HTTP HEAD, certificat HTTPS ou Nmap optionnel sans scripts.
- CVE uniquement après identification d'un produit ou d'une version probable.
- Confirmation d'autorisation obligatoire dans l'interface avant découverte ou scan.
- Avertissement explicite pour les adresses publiques.
- Limite par défaut à 256 hôtes par opération graphique.
- Journalisation rotative locale pour éviter les fichiers de logs sans limite.

## Données sensibles

- Aucune clé API NVD n'est stockée.
- Les rapports et bases locales ne contiennent pas de mot de passe.
- Les caches CVE ne contiennent que des réponses publiques NVD/CISA.

## Limites connues

- Une CVE associée reste potentielle tant qu'elle n'a pas été vérifiée par configuration exacte, patch level et contexte d'exposition.
- Certains équipements bloquent ICMP ; NetScope combine donc ARP, ICMP, TCP et table ARP.
- Le fabricant MAC dépend d'une base OUI locale minimale et peut afficher `Inconnu`.
