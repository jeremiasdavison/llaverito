export class HttpError extends Error {
  status: number;
  code?: string;
  details?: Record<string, string | number | boolean | null>;

  constructor(
    status: number,
    message: string,
    code?: string,
    details?: Record<string, string | number | boolean | null>,
  ) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export class ConfigError extends Error {
  constructor() {
    super("service is not configured");
    this.name = "ConfigError";
  }
}
