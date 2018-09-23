# Keycloak Login Page with Recaptcha

This module contains the project extension and theme for the login page with google recaptcha.

## Getting Started

### Prerequisites
* Keycloak 4.4.0-Final

### Installation
Click [here](https://www.keycloak.org/docs/latest/getting_started/index.html) for guidelines on how to install keycloak.

## Deployment
### Packaging
Package the project by running the command below

```
$ mvn clean package
```

### Deploying

Deploy the packaged jar and the theme located inside the theme folder to keycloak.

### Applying extension

1. Login to Admin Console.
2. Select realm.
3. Go to Authentication page.
4. Copy Browser authentication.
5. Delete Username Password Form execution.
6. Add Username Password Form with Recaptcha.
7. Change requirement to REQUIRED.
8. Add Recaptcha Site Key, Recaptcha Secret and Recaptcha login attempts in configuration.