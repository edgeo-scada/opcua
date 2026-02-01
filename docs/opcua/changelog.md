# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-02-01

### Ajouté

#### Client
- Client OPC UA TCP complet avec support des sessions
- Navigation dans l'espace d'adressage (Browse, BrowseNext)
- Lecture d'attributs (Read) avec support de tous les types de données
- Écriture d'attributs (Write) avec validation des types
- Appel de méthodes (Call)
- Découverte des endpoints (GetEndpoints)
- Reconnexion automatique avec backoff exponentiel
- Support des politiques de sécurité (None, Basic128Rsa15, Basic256, Basic256Sha256)
- Support des modes de sécurité (None, Sign, SignAndEncrypt)
- Authentification anonyme, par mot de passe et par certificat
- Métriques intégrées (latence, compteurs, connexions)
- Logging structuré via slog

#### Subscriptions
- Création et suppression de subscriptions
- Création de monitored items
- Réception des notifications de changement de données
- Configuration des intervalles de publication et d'échantillonnage

#### Serveur
- Serveur OPC UA TCP avec support multi-clients
- Gestion de l'espace d'adressage
- Support des subscriptions et monitored items
- Authentification personnalisable
- Contrôle d'accès par noeud

#### Pool de connexions
- Pool de connexions avec gestion automatique
- Health checks périodiques
- Statistiques et métriques

#### CLI (opcuacli)
- Commande `browse` - Navigation dans l'espace d'adressage
- Commande `read` - Lecture de valeurs de noeuds
- Commande `write` - Écriture de valeurs
- Commande `subscribe` - Souscription aux changements
- Commande `info` - Informations sur le serveur
- Commande `version` - Affichage de la version

### Types de données supportés
- Boolean
- SByte, Byte
- Int16, UInt16
- Int32, UInt32
- Int64, UInt64
- Float, Double
- String
- DateTime
- GUID
- ByteString
- NodeID
- StatusCode
- QualifiedName
- LocalizedText

## [Unreleased]

### Prévu
- Support de HistoryRead et HistoryUpdate
- Support de RegisterNodes et UnregisterNodes
- Support de TranslateBrowsePathsToNodeIds
- Amélioration du support des alarmes et événements
- Support de la découverte automatique (FindServers)
- Mode cluster avec failover automatique
