import { OpenAPI, AuthService, type LoginDto } from '../src';
import { isTypedSdkError } from '../src/errors';

OpenAPI.BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:3001';
OpenAPI.TOKEN = async () => process.env.NESTERA_ACCESS_TOKEN;
OpenAPI.CORRELATION_ID = () => crypto.randomUUID();
OpenAPI.TIMEOUT_MS = 15000;
OpenAPI.RETRY_GET_ATTEMPTS = 2;
OpenAPI.MIDDLEWARE = [
  {
    onRequest: async (context) => {
      console.debug('Nestera SDK request', context.options.method, context.url);
      return context;
    },
  },
];

export async function loginExample(payload: LoginDto) {
  try {
    return await AuthService.authControllerLogin(payload);
  } catch (error) {
    const body = (error as { body?: unknown }).body;

    if (isTypedSdkError(body)) {
      return {
        ok: false,
        errorCode: body.errorCode,
        message: body.message,
        correlationId: body.correlationId,
      };
    }

    throw error;
  }
}
