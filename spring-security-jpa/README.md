## Getting Started

### Prerequisites

- Git
- Java 11
- Maven

### Cloning & Running the App

1.  Open your terminal or command prompt.

2.  Clone the repository using Git:

    ```bash
    git clone https://github.com/arsy786/spring-security-tutorials.git
    ```

3.  Navigate to the cloned repository's root directory:

    ```bash
    cd spring-security-tutorials
    ```

4.  Navigate to the respective service directory:

    ```bash
    cd <service-directory>
    ```

    Replace `<service-directory>` with either `spring-security-jpa`, `spring-security-jdbc`, `spring-security-jwt` or `jwt-oauth2-demo`.

5.  Run the following Maven command to build and start the service:

    ```bash
    # For Maven
    mvn spring-boot:run

    # For Maven Wrapper
    ./mvnw spring-boot:run
    ```

The application should now be running on `localhost:8080`.
