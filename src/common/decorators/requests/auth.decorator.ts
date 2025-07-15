import { applyDecorators, UseGuards } from '@nestjs/common';
import { ApiSecurity } from '@nestjs/swagger';

import { RequireAuth } from '@/common/guards/auth.guard';
import { ApiUnauthorizedError } from '../response/api-response-error.decorator';

/**
 * Combined decorator that applies RequireAuth guard and adds Swagger documentation
 * Automatically documents 401 Unauthorized response
 * Indicates that the route is protected and requires Clerk authentication
 */
export function ProtectFromUnauthorized() {
  return applyDecorators(
    UseGuards(RequireAuth),
    ApiSecurity('Login', []),
    ApiUnauthorizedError({
      description:
        '🔒 This route is protected - Authentication required. Invalid or missing jwt token',
    }),
  );
}
