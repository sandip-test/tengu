import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  mixin,
  Type,
} from '@nestjs/common';
import { verifyToken } from '@/lib/auth.lib';
import { UserRoleEnum } from '@/db/schema';
import { db } from '@/db';

/**
 * Auth guard that checks for a valid JWT token in the request headers.
 * If the token is valid, it extracts user info and attaches it to the request.
 * Admins can access any route. Other roles must match `allowedRoles`.
 */
export function RequireAuth(allowedRoles?: UserRoleEnum[]): Type<CanActivate> {
  @Injectable()
  class RoleGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const request = context.switchToHttp().getRequest();
      const authHeader = request.headers.authorization;

      if (!authHeader) {
        throw new UnauthorizedException('Authorization token is missing');
      }

      const token: string = authHeader.split(' ')[1];
      const data = verifyToken(token);
      if (!data) {
        throw new UnauthorizedException('Invalid or expired token');
      }

      const user = await db.query.users.findFirst({
        where: (user, { eq }) => eq(user.id, data.id),
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // ✅ Admins can access everything
      if (user.role !== UserRoleEnum.ADMIN) {
        if (allowedRoles && !allowedRoles.includes(user.role!)) {
          throw new ForbiddenException(
            'You do not have permission to access this resource',
          );
        }
      }

      request.user = user; // Attach user info to request

      return true;
    }
  }

  return mixin(RoleGuard);
}
