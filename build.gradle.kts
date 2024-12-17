
plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation ("commons-io:commons-io:2.14.0")
}

// Configurazione per il JAR
tasks.jar {
    manifest {
        attributes(
                "Main-Class" to "MainTest" // Specifica la tua classe principale con il metodo `main`
        )
    }

    // Includi tutte le dipendenze nel JAR (per un JAR eseguibile con tutte le librerie)
    from({
        configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) }
    }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    }
}

// Task per costruire l'applicazione
tasks.build {
    dependsOn(tasks.jar)
}

tasks.test {
    useJUnitPlatform()
}