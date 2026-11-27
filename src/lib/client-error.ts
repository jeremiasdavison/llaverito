export function errorMessage(cause: unknown) {
  return cause instanceof Error && cause.message ? cause.message : "No se pudo completar";
}
