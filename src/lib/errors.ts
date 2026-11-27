export class HttpError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export class ConfigError extends Error {
  constructor(message = "service is not configured") {
    super(message);
    this.name = "ConfigError";
  }
}

export class DatabaseConfigError extends ConfigError {
  constructor() {
    super("database url is not configured");
    this.name = "DatabaseConfigError";
  }
}

export class DatabaseError extends ConfigError {
  constructor() {
    super("database is unavailable");
    this.name = "DatabaseError";
  }
}

export const CONFIG_MISSING_MESSAGE =
  "Falta configurar la base o las claves. Revisá DATABASE_URL, BETTER_AUTH_SECRET y ENCRYPTION_KEY.";

export const DATABASE_MISSING_MESSAGE =
  "Falta la base. Definí DATABASE_URL (o POSTGRES_URL) con el connection string de Neon.";

export const DATABASE_UNAVAILABLE_MESSAGE =
  "La base de datos no está disponible. Conectá Neon y revisá DATABASE_URL.";
