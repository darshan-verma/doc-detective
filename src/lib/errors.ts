export type ErrorCode =
  | "BAD_REQUEST"
  | "EMPTY_FILE"
  | "FILE_TOO_LARGE"
  | "NOT_FOUND"
  | "RATE_LIMITED"
  | "SIGNATURE_INVALID"
  | "SIMILAR_CERTIFICATE_EXISTS"
  | "INTERNAL";

export class AppError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly status: number = 400,
    /** Extra fields merged into the error JSON body (e.g. candidates). */
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export function errorResponse(error: unknown): Response {
  if (error instanceof AppError) {
    return Response.json(
      {
        error: {
          code: error.code,
          message: error.message,
          ...(error.details ?? {}),
        },
      },
      { status: error.status },
    );
  }

  console.error(error);
  return Response.json(
    { error: { code: "INTERNAL", message: "An unexpected error occurred" } },
    { status: 500 },
  );
}
