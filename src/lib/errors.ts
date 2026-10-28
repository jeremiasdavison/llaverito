export class HttpError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export class ConfigError extends Error {
  constructor() {
    super("service is not configured");
    this.name = "ConfigError";
  }
}
